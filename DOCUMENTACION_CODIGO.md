# Documentación de Código — LogGuardV2

---

## Índice

1. [FileWatcherLive](#filewatcherlive)
2. [PostgreSqlLogParser](#postgresqllogparser)
3. [SqlTokenizer](#sqltokenizer)
4. [NfaEngine](#nfaengine)
5. [NfaLoader](#nfaloader)
6. [LogLiveWatcher](#nfamodule--automaonprofile)
7. [NFAModule / AutomatonProfile](#nfamodule--automatonprofile)
8. [LogEntry](#logentry)
9. [AppSettings / SettingsService](#appsettings--settingsservice)
10. [MainWindow — Convertidores WPF](#mainwindow--convertidores-wpf)

---

## FileWatcherLive

**Archivo:** `FileWatcherLive.cs`  
**Namespace:** `LogGuardV2`  
**Implementa:** `IDisposable`

Monitorea un directorio de logs mediante polling periódico cada 500 ms. Detecta nuevas líneas añadidas y rotación de archivos.

### Constructor

```csharp
public FileWatcherLive(string logDirectory, string watchPattern, bool followRotation)
```

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `logDirectory` | `string` | Ruta al directorio de logs de PostgreSQL |
| `watchPattern` | `string` | Patrón glob para filtrar archivos (ej. `"postgresql-*.log"`) |
| `followRotation` | `bool` | Si `true`, sigue el nuevo archivo cuando se detecta rotación |

### Eventos

```csharp
public event Action<IReadOnlyList<string>>? NewLines;
```

Disparado cada ciclo de polling con la lista de líneas nuevas leídas. La lista está vacía si no hubo cambios.

### Métodos públicos

```csharp
public void Start()
```
Inicia el timer de polling. Lanza `InvalidOperationException` si ya está en ejecución.

```csharp
public void Stop()
```
Detiene el polling. El timer se cancela en el siguiente tick.

```csharp
public void Dispose()
```
Para el polling y libera el timer. Implementa `IDisposable`.

### Métodos privados clave

```csharp
private void CheckRotation()
```
Compara el tamaño del archivo actual con `_lastPosition`. Si el archivo es más pequeño (o fue reemplazado), registra rotación y reinicia la posición de lectura.

```csharp
private IReadOnlyList<string> ReadTail()
```
Lee desde `_lastPosition` hasta el final del archivo. Actualiza `_lastPosition`. Devuelve lista vacía si no hay líneas nuevas.

### Ejemplo de uso

```csharp
var watcher = new FileWatcherLive(@"C:\pgdata\log", "*.log", followRotation: true);
watcher.NewLines += lines => {
    foreach (var line in lines)
        Console.WriteLine(line);
};
watcher.Start();
// ...
watcher.Stop();
watcher.Dispose();
```

---

## PostgreSqlLogParser

**Archivo:** `PostgreSqlLogParser.cs`  
**Namespace:** `LogGuardV2`  
**Clase:** estática

Parsea líneas de log en el formato estándar de PostgreSQL con `log_line_prefix = '%m [%p] %q%u@%h %d '`.

### Enum PgLogLineType

```csharp
public enum PgLogLineType
{
    Statement,            // "statement: SELECT ..."
    Duration,             // "duration: 12.345 ms"
    ConnectionReceived,   // "connection received: host=..."
    ConnectionAuthorized, // "connection authorized: user=... database=..."
    Disconnection,        // "disconnection: ..."
    Error,
    Fatal,
    Warning,
    Unknown
}
```

### Clase PgLogEntry

Contenedor de los campos extraídos de una línea de log:

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `LineType` | `PgLogLineType` | Tipo de línea identificado |
| `Timestamp` | `DateTimeOffset` | Timestamp del evento |
| `Pid` | `int` | Process ID de PostgreSQL |
| `Level` | `string` | Severidad textual (LOG, ERROR, etc.) |
| `User` | `string?` | Usuario de la sesión (disponible en Statement, Duration) |
| `Host` | `string?` | Host de origen |
| `Database` | `string?` | Nombre de base de datos |
| `Query` | `string?` | Consulta SQL (solo en Statement) |
| `DurationMs` | `double` | Duración en ms (solo en Duration) |
| `RawMessage` | `string` | Mensaje completo sin parsear |

### Métodos estáticos

```csharp
public static PgLogEntry? TryParse(string line)
```

**Parámetro:** `line` — línea completa de log.  
**Retorno:** `PgLogEntry` con campos extraídos, o `null` si la línea no coincide con ningún patrón conocido.  
**Complejidad:** O(1) — regex pre-compiladas de longitud acotada.

```csharp
public static bool LooksLikeHeader(string line)
```

Determina si una línea es continuación de log multi-línea (comienza con tabulación o espacios). Usado por `LogLiveWatcher` para bufferizar líneas parciales.

**Retorno:** `true` si la línea es continuación de la anterior.

```csharp
public static DateTimeOffset? ResolveTimestamp(string raw, string timezone)
```

**Parámetros:**
- `raw` — string de timestamp en formato PostgreSQL (ej. `"2024-01-15 14:30:00.123 UTC"`).
- `timezone` — zona horaria para convertir si el timestamp no tiene zona explícita.

**Retorno:** `DateTimeOffset` normalizado, o `null` si el formato no es reconocido.

### Ejemplo de uso

```csharp
string line = "2024-01-15 14:30:00.123 UTC [1234] app@192.168.1.1 mydb LOG:  statement: SELECT * FROM users WHERE id=1";
var entry = PostgreSqlLogParser.TryParse(line);

if (entry != null && entry.LineType == PgLogLineType.Statement)
{
    Console.WriteLine($"PID: {entry.Pid}, Query: {entry.Query}");
}
```

---

## SqlTokenizer

**Archivo:** `SqlTokenizer.cs`  
**Namespace:** `LogGuardV2`  
**Clase:** estática

Convierte una cadena SQL en una lista de tokens canónicos mediante un pipeline de 4 fases resistente a técnicas de evasión.

### Método principal

```csharp
public static List<string> Tokenize(string sql)
```

**Parámetro:** `sql` — cadena SQL en bruto (puede contener caracteres especiales, comentarios, encoding alternativo).  
**Retorno:** `List<string>` de tokens canónicos. Lista vacía si `sql` es null o whitespace.  
**Complejidad:** O(n) donde n es la longitud de `sql`.

### Fases de procesamiento

#### Fase 1 — Normalización (método privado `Normalize`)

Máquina de estados carácter a carácter:

| Técnica de evasión | Tratamiento |
|--------------------|-------------|
| Comentarios de bloque `/* ... */` | Eliminados (fusionados con lo que rodean) |
| Comentarios de línea `-- ...` | Eliminados hasta fin de línea |
| Literales hex `0x53454C454354` | Decodificados a caracteres ASCII |
| Percent-encoding `%53%45%4C` | Decodificados a caracteres ASCII |
| Escapes unicode `S` | Decodificados |
| Dollar-quoting PostgreSQL `$$...$$` | Stripped |

#### Fase 2 — Detección de tautologías (método privado `ReplaceTautologies`)

5 regex pre-compiladas con longitud acotada:

| Patrón | Ejemplo | Token resultante |
|--------|---------|-----------------|
| `\b(\d+)\s*=\s*\1\b` | `1=1` | `TAUTOLOGY` |
| `'([^']{0,50})'\s*=\s*'\1'` | `'a'='a'` | `TAUTOLOGY` |
| `\b(\w{1,30})\s*=\s*\1\b` | `x=x` | `TAUTOLOGY` |
| `\b1\s*>\s*0\b` | `1>0` | `TAUTOLOGY` |
| `\b1\s*<>\s*2\b` | `1<>2` | `TAUTOLOGY` |

#### Fase 3 — Escaneo (método privado `Scan`)

Máquina de estados sin regex (ReDoS-proof):

Tipos de token producidos:
- `SELECT`, `FROM`, `WHERE`, `UNION`, `UNION_ALL`, `OR`, `AND`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE` — palabras clave SQL
- `SLEEP`, `BENCHMARK`, `INFORMATION_SCHEMA`, `SUPERUSER` — tokens de riesgo canónicos
- `TAUTOLOGY` — inyectado por fase 2
- `IDENT` — identificadores genéricos no reconocidos
- `STRING` — literales de cadena
- `NUMBER` — literales numéricos
- `STAR` — `*`
- `EQUALS`, `NEQ`, `LT`, `GT`, `LEQ`, `GEQ` — operadores de comparación
- `CONCAT` — `||`

Diccionario de canonicalización (~160 entradas, selección):

| Entrada SQL | Token canónico |
|-------------|----------------|
| `ILIKE` | `LIKE` |
| `PG_SLEEP` | `SLEEP` |
| `REPLICATION` | `SUPERUSER` |
| `INFORMATION_SCHEMA` | `INFORMATION_SCHEMA` |
| `SYS` | `INFORMATION_SCHEMA` |
| `DUAL` | `IDENT` |
| `WAITFOR` | `SLEEP` |

#### Fase 4 — Fusión (método privado `Fuse`)

Recorre la lista de tokens y consolida secuencias:

| Secuencia | Token resultante |
|-----------|-----------------|
| `UNION`, `ALL` | `UNION_ALL` |
| `INTO`, `OUTFILE` | `INTO_OUTFILE` |
| `INTO`, `DUMPFILE` | `INTO_DUMPFILE` |
| `WAITFOR`, `DELAY` | `WAITFOR_DELAY` |
| `LOAD`, `DATA` | `LOAD_DATA` |

### Ejemplos de tokenización

**Consulta limpia:**
```
Entrada: "SELECT id, name FROM users WHERE id = 42"
Salida:  ["SELECT", "IDENT", "IDENT", "FROM", "IDENT", "WHERE", "IDENT", "EQUALS", "NUMBER"]
```

**SQL Injection con comentario:**
```
Entrada: "SELECT * FROM users WHERE 1=1 -- comentario"
Salida:  ["SELECT", "STAR", "FROM", "IDENT", "WHERE", "TAUTOLOGY"]
```

**Evasión hex:**
```
Entrada: "0x53454C454354 * FROM users"
Salida:  ["SELECT", "STAR", "FROM", "IDENT"]
```

**UNION attack:**
```
Entrada: "SELECT id FROM t UNION ALL SELECT password FROM pg_shadow"
Salida:  ["SELECT", "IDENT", "FROM", "IDENT", "UNION_ALL", "SELECT", "IDENT", "FROM", "IDENT"]
```

---

## NfaEngine

**Archivo:** `NfaEngine.cs`  
**Namespace:** `LogGuardV2`

Motor NFA basado en simulación powerset. Realiza búsqueda de subcadena (el patrón puede aparecer en cualquier posición de la secuencia de tokens).

### Constructor

```csharp
public NfaEngine(AutomatonProfile profile)
```

**Parámetro:** `profile` — perfil NFA deserializado. El constructor precomputa las tablas de transición y los conjuntos de estados inicio/aceptación.

**Dependencias:** `NFAModule.AutomatonProfile`.

### Propiedades públicas

| Propiedad | Tipo | Descripción |
|-----------|------|-------------|
| `ProfileId` | `string` | ID del perfil NFA (ej. `"pgsql-sqli-v2"`) |
| `ThreatType` | `string` | Tipo de amenaza para `LogEntry.ThreatType` |
| `Severity` | `string` | Severidad (`"Critical"`, `"High"`, `"Medium"`, `"Low"`) |
| `Description` | `string` | Descripción legible del perfil |

### Método principal

```csharp
public bool Run(IReadOnlyList<string> tokens)
```

**Parámetro:** `tokens` — lista de tokens producida por `SqlTokenizer.Tokenize()`.  
**Retorno:** `true` si el autómata acepta la secuencia (amenaza detectada); `false` en caso contrario.  
**Complejidad:** O(tokens.Count × |estados|).

**Algoritmo:**
1. Inicializar conjunto activo con todos los estados de inicio.
2. Para cada token:
   - Re-inyectar estados de inicio (permite match en cualquier posición).
   - Aplicar transiciones: `next = { delta[s][token] | s ∈ active }`.
   - Si la intersección con estados de aceptación no es vacía → retornar `true` (si `RequireAbsentTokens` no viola la condición).
3. Si se procesaron todos los tokens sin aceptar → retornar `false`.

**Post-condición RequireAbsentTokens:**
Si el autómata acepta pero la lista de tokens contiene algún token de `RequireAbsentTokens`, el resultado se fuerza a `false`.

### Ejemplo de uso

```csharp
var profile = NfaLoader.LoadAllRaw().First(p => p.Id == "pgsql-sqli-v2");
var engine = new NfaEngine(profile);

var tokens = SqlTokenizer.Tokenize("SELECT * FROM users WHERE 1=1");
bool isInjection = engine.Run(tokens); // true
```

---

## NfaLoader

**Archivo:** `NfaLoader.cs`  
**Namespace:** `LogGuardV2`  
**Clase:** estática

Carga y deserializa perfiles NFA desde archivos JSON en la carpeta `NFA/`.

### Métodos estáticos

```csharp
public static IReadOnlyList<NfaEngine> LoadAll()
```

Busca todos los archivos `*.json` en `<AppDirectory>/NFA/`, los deserializa como `AutomatonProfile` y construye un `NfaEngine` por cada perfil válido.

**Retorno:** Lista de engines listos para usar. Lista vacía si no hay archivos o todos son inválidos.  
**Excepciones:** Archivos con JSON malformado son descartados con log de error (no propagan excepción).

```csharp
public static IReadOnlyList<AutomatonProfile> LoadAllRaw()
```

Misma operación pero devuelve los modelos `AutomatonProfile` sin construir engines. Usado por la pestaña **Modules** para mostrar metadatos.

**Retorno:** Lista de perfiles deserializados.

### Ejemplo de uso

```csharp
// Cargar engines para detección
var engines = NfaLoader.LoadAll();

// Cargar perfiles para mostrar en UI
var profiles = NfaLoader.LoadAllRaw();
foreach (var p in profiles)
    Console.WriteLine($"{p.Id}: {p.Metadata.Severity} — {p.Metadata.Description}");
```

---

## LogLiveWatcher

**Archivo:** `LogLiveWatcher.cs`  
**Namespace:** `LogGuardV2`  
**Implementa:** `IDisposable`

Orquestador del pipeline de análisis. Coordina la adquisición, el parsing, la correlación de contexto, la tokenización y la detección de amenazas.

### Constructor

```csharp
public LogLiveWatcher(AppSettings settings)
```

**Parámetro:** `settings` — configuración de la aplicación. El constructor crea internamente un `FileWatcherLive` y carga los engines NFA.

### Eventos

```csharp
public event Action<LogEntry>? EntryDetected;
```

Disparado en el UI thread (via `Dispatcher.InvokeAsync`) cada vez que se completa el análisis de una entrada de log relevante.

### Métodos públicos

```csharp
public void Start()
```
Inicia `FileWatcherLive` y lanza la tarea consumidora del `Channel`.

```csharp
public void Stop()
```
Detiene el polling y completa el canal. La tarea consumidora termina al vaciar el canal.

```csharp
public void ReloadEngines()
```
Recarga los perfiles NFA desde disco y reemplaza el array de engines de forma atómica (`Interlocked.Exchange`). Thread-safe: no requiere detener el monitoreo.

```csharp
public void FlushStale()
```
Expulsa entradas PID sin evento de desconexión registrado (limpieza de memoria para sesiones largas o conexiones rotas). Thread-safe: escribe en el `Channel`.

```csharp
public void Dispose()
```
Libera recursos: para el watcher, completa el canal, espera que termine la tarea consumidora.

### Flujo interno (método privado ConsumeEntries)

```csharp
private async Task ConsumeEntries(CancellationToken ct)
```

Loop `await foreach` sobre `Channel.Reader`. Para cada línea:

1. `PostgreSqlLogParser.TryParse(line)` → `PgLogEntry?`
2. Actualizar contexto PID según `LineType`.
3. Si `Statement`:
   - `SqlTokenizer.Tokenize(entry.Query)` → `List<string>`
   - `RunEngines(tokens)` → `(bool isInjected, string? threatType)`
   - Si brute-force pattern: evaluar `_bfWindow[user@host]`
4. Si `Duration`: parear con `_pidPending[pid]` → construir `LogEntry` completo.
5. Actualizar contadores `Interlocked`.
6. Invocar `EntryDetected` en UI thread.

### Detección de fuerza bruta (método privado)

```csharp
private bool CheckBruteForce(string userHost, DateTime now)
```

Mantiene `_bfWindow: Dictionary<string, Queue<DateTime>>` por `user@host`.

Algoritmo:
1. Obtener (o crear) cola para `userHost`.
2. `Enqueue(now)`.
3. Eliminar entradas más antiguas que 60 s desde el frente.
4. Retornar `true` si `Count >= 5`.

---

## NFAModule / AutomatonProfile

**Archivo:** `NFAModule.cs`  
**Namespace:** `LogGuardV2`

Modelo de datos completo para un perfil NFA. Deserializado directamente desde JSON por `NfaLoader`.

### Clases anidadas

```csharp
public sealed class AutomatonProfile
{
    public string Id { get; set; }
    public TargetDefinition Target { get; set; }
    public string[] Alphabet { get; set; }
    public StateDefinition[] States { get; set; }
    public TransitionDefinition[] Transitions { get; set; }
    public string[] RequireAbsentTokens { get; set; }
    public MetadataDefinition Metadata { get; set; }
}

public sealed class TargetDefinition
{
    public string Engine { get; set; }       // "postgresql"
    public string VersionMin { get; set; }   // "12.0"
}

public sealed class StateDefinition
{
    public string Id { get; set; }
    public bool IsStart { get; set; }
    public bool IsAccept { get; set; }
}

public sealed class TransitionDefinition
{
    public string From { get; set; }
    public string Symbol { get; set; }
    public string To { get; set; }
}

public sealed class MetadataDefinition
{
    public string Severity { get; set; }     // "Critical|High|Medium|Low"
    public string Description { get; set; }
    public string[] Tags { get; set; }
}
```

### Ejemplo de perfil mínimo funcional

```json
{
  "id": "pgsql-custom-v1",
  "target": { "engine": "postgresql", "version_min": "12.0" },
  "alphabet": ["DROP", "TABLE"],
  "states": [
    { "id": "q0",      "is_start": true,  "is_accept": false },
    { "id": "q_drop",  "is_start": false, "is_accept": false },
    { "id": "q_final", "is_start": false, "is_accept": true  }
  ],
  "transitions": [
    { "from": "q0",     "symbol": "DROP",  "to": "q_drop"  },
    { "from": "q_drop", "symbol": "TABLE", "to": "q_final" }
  ],
  "require_absent_tokens": [],
  "metadata": {
    "severity": "Critical",
    "description": "Detección de DROP TABLE",
    "tags": ["ddl", "destructive"]
  }
}
```

---

## LogEntry

**Archivo:** `LogEntry.cs`  
**Namespace:** `LogGuardV2`

Modelo inmutable de fila para el DataGrid. Construido al completarse el par Statement+Duration o al recibir evento de error/fatal.

### Propiedades

```csharp
public sealed class LogEntry
{
    public DateTimeOffset Timestamp { get; init; }
    public int Pid { get; init; }
    public string Level { get; init; }      // "FATAL"|"ERROR"|"WARN"|"INFO"|"DEBUG"|"LOG"
    public string UserHost { get; init; }   // "usuario@host"
    public string Database { get; init; }
    public string Query { get; init; }
    public double Duration { get; init; }   // milisegundos
    public bool IsInjected { get; init; }
    public string? ThreatType { get; init; } // "SQLI"|"BRUTEFORCE"|"EXFIL"|"PRIVESC"|"DISCOVERY"|null
}
```

**Inmutabilidad:** todos los campos son `init`-only. Construidos con object initializer una sola vez en `LogLiveWatcher`.

### Ejemplo de construcción

```csharp
var entry = new LogEntry
{
    Timestamp  = DateTimeOffset.UtcNow,
    Pid        = 1234,
    Level      = "LOG",
    UserHost   = "app@192.168.1.10",
    Database   = "produccion",
    Query      = "SELECT * FROM usuarios WHERE id=1 OR 1=1",
    Duration   = 12.5,
    IsInjected = true,
    ThreatType = "SQLI"
};
```

---

## AppSettings / SettingsService

**Archivos:** `AppSettings.cs`, `SettingsService.cs`  
**Namespace:** `LogGuardV2`

### AppSettings

POCO de configuración con 20 propiedades. Todos los campos tienen valores por defecto seguros.

**Propiedades de fuente y monitoreo:**

| Propiedad | Tipo | Defecto | Descripción |
|-----------|------|---------|-------------|
| `LogDirectory` | `string` | `""` | Ruta al directorio de logs |
| `WatchPattern` | `string` | `"*.log"` | Patrón glob de archivos |
| `Timezone` | `string` | Local | Zona horaria para timestamps |
| `LogLineFormat` | `string` | Estándar PG | Formato de `log_line_prefix` |
| `FollowRotation` | `bool` | `true` | Seguir rotación de archivo |
| `ReplayOnStart` | `bool` | `false` | Releer archivo completo al iniciar |

**Propiedades de parser:**

| Propiedad | Tipo | Descripción |
|-----------|------|-------------|
| `ParseCoreFields` | `bool` | Extraer nivel, pid, timestamp |
| `ParseConnectionDetails` | `bool` | Extraer usuario, host, base de datos |
| `ParseQueryDetails` | `bool` | Extraer query y duración |
| `ParseSystemMetrics` | `bool` | Extraer métricas del sistema |
| `ParseRawMessage` | `bool` | Preservar mensaje en bruto |
| `RedactPasswords` | `bool` | Redactar contraseñas detectadas |

**Propiedades de alertas:**

| Propiedad | Tipo | Descripción |
|-----------|------|-------------|
| `AlertWebhookUrl` | `string` | URL de webhook externo |
| `AlertMinLevel` | `string` | Nivel mínimo para alertas |
| `DesktopNotifications` | `bool` | Notificaciones de escritorio Windows |
| `AudioBeepOnFatal` | `bool` | Beep en eventos FATAL |

### SettingsService

Clase estática. Sin estado propio.

```csharp
public static AppSettings Load()
```

Lee `%AppData%\LogGuardV2\settings.json`. Si el archivo no existe, retorna `new AppSettings()` con valores por defecto. Si el JSON está malformado, retorna instancia por defecto y registra el error.

**Retorno:** `AppSettings` — nunca null.

```csharp
public static void Save(AppSettings settings)
```

Serializa `settings` a JSON con indentación y escribe en `%AppData%\LogGuardV2\settings.json`. Crea el directorio si no existe.

**Parámetro:** `settings` — instancia a persistir.  
**Excepciones:** Propaga `IOException` si no puede escribir el archivo.

### Ejemplo de uso

```csharp
// Cargar configuración al iniciar
var settings = SettingsService.Load();
settings.LogDirectory = @"C:\pgdata\log";
SettingsService.Save(settings);

// Reconstruir watcher con nueva config
var watcher = new LogLiveWatcher(settings);
```

---

## MainWindow — Convertidores WPF

**Archivo:** `MainWindow.xaml.cs`  
**Namespace:** `LogGuardV2`

Convertidores de valor implementados como clases anidadas privadas. Todos implementan `IValueConverter`.

### LevelToSevColorConverter

```csharp
// Entrada: string (Level)
// Salida: SolidColorBrush
// Mapeo:
// "FATAL" → Rojo intenso
// "ERROR" → Naranja
// "WARN"  → Amarillo
// "INFO"  → Gris claro
// "DEBUG" → Gris oscuro
// "LOG"   → Blanco/neutro
```

### LevelToBadgeFgConverter / LevelToBadgeBgConverter / LevelToBadgeBorderConverter

Variantes para el color de texto, fondo y borde de los badges de severidad en el DataGrid.

### BoolToInjTextConverter

```csharp
// Entrada: bool (IsInjected)
// Salida: string
// true  → "INYECTADO"
// false → ""
```

### BoolToInjFgConverter / BoolToInjBgConverter / BoolToInjBorderConverter

Color de texto, fondo y borde para la columna `Injected` según si la consulta fue detectada como inyección.

### DurFmtConverter

```csharp
// Entrada: double (Duration en ms)
// Salida: string formateada
// < 1    → "< 1 ms"
// < 1000 → "123 ms"
// ≥ 1000 → "1.23 s"
```

### Ejemplo de uso en XAML

```xml
<DataGridTextColumn Header="Duration"
    Binding="{Binding Duration, Converter={StaticResource DurFmtConverter}}" />

<DataGridTextColumn Header="Level"
    Binding="{Binding Level}">
    <DataGridTextColumn.ElementStyle>
        <Style TargetType="TextBlock">
            <Setter Property="Foreground"
                Value="{Binding Level, Converter={StaticResource LevelToSevColorConverter}}" />
        </Style>
    </DataGridTextColumn.ElementStyle>
</DataGridTextColumn>
```

---

## Notas de implementación

### Gestión de memoria del DataGrid

El DataGrid mantiene un máximo de 5,000 entradas (`ObservableCollection<LogEntry>`). Al superar ese límite, se elimina la entrada más antigua (índice final de la colección). La inserción siempre es en posición 0 (más reciente primero).

### Hot reload de engines

```csharp
// LogLiveWatcher.ReloadEngines()
var newEngines = NfaLoader.LoadAll().ToArray();
Interlocked.Exchange(ref _engines, newEngines);
// El consumer task leerá el nuevo array en su próximo ciclo sin lock
```

### Bufferización de líneas multi-línea de PostgreSQL

PostgreSQL puede dividir un `statement:` largo en múltiples líneas (continuación con tabulación). `LogLiveWatcher` detecta líneas de continuación con `PostgreSqlLogParser.LooksLikeHeader()` y las acumula en `_pendingLine` antes de escribir en el canal.

```csharp
// Pseudocódigo del bufferizado
foreach (var line in newLines)
{
    if (PostgreSqlLogParser.LooksLikeHeader(line))
        _pendingLine += line;  // concatenar continuación
    else
    {
        if (_pendingLine.Length > 0)
            channel.Writer.TryWrite(_pendingLine);  // emitir línea completa anterior
        _pendingLine = line;
    }
}
```
