# Documentación Técnica — LogGuardV2

---

## Índice

1. [Arquitectura del sistema](#arquitectura-del-sistema)
2. [Componentes y responsabilidades](#componentes-y-responsabilidades)
3. [Flujo de datos](#flujo-de-datos)
4. [Patrones de diseño identificados](#patrones-de-diseño-identificados)
5. [Interfaces y contratos relevantes](#interfaces-y-contratos-relevantes)
6. [Variables de entorno y configuración](#variables-de-entorno-y-configuración)
7. [Modelo de datos NFA](#modelo-de-datos-nfa)
8. [Concurrencia y sincronización](#concurrencia-y-sincronización)
9. [Métricas y KPI en tiempo real](#métricas-y-kpi-en-tiempo-real)
10. [Perfiles de detección incluidos](#perfiles-de-detección-incluidos)
11. [Rendimiento y complejidad algorítmica](#rendimiento-y-complejidad-algorítmica)

---

## Arquitectura del sistema

LogGuardV2 es una aplicación de escritorio Windows WPF de proceso único con arquitectura **pipeline orientado a eventos**. No expone APIs de red ni requiere procesos externos.

### Vista de alto nivel

```
┌─────────────────────────────────────────────────────────┐
│                      UI Thread (WPF)                    │
│  MainWindow ─ DataGrid ─ KPI Bar ─ Charts ─ Settings   │
└───────────────────────┬─────────────────────────────────┘
                        │ Dispatcher.InvokeAsync (EntryDetected)
┌───────────────────────▼─────────────────────────────────┐
│              LogLiveWatcher (Engine Orchestrator)        │
│  Channel<string> MPSC consumer task (Task.Run)          │
│  PID context dicts ─ BruteForce window ─ NFA engines   │
└──────────────┬───────────────────────┬──────────────────┘
               │ Channel.Writer        │ NfaEngine[] (Interlocked swap)
┌──────────────▼──────┐    ┌──────────▼──────────────────┐
│  FileWatcherLive    │    │  NfaEngine (×N, per profile) │
│  Timer poll 500ms   │    │  Powerset NFA simulation     │
│  File rotation      │    │  + RequireAbsentTokens check │
└─────────────────────┘    └──────────────────────────────┘
                                        ▲
                           ┌────────────┴───────────────┐
                           │  NfaLoader (static)        │
                           │  JSON → AutomatonProfile   │
                           └────────────────────────────┘
```

### Capas lógicas

| Capa | Componentes | Responsabilidad |
|------|-------------|-----------------|
| **UI** | `MainWindow.xaml`, `MainWindow.xaml.cs`, `App.xaml` | Presentación, interacción, KPI, gráficos |
| **Orquestación** | `LogLiveWatcher` | Coordinación del pipeline, contexto de sesión, ventana brute-force |
| **Adquisición** | `FileWatcherLive` | Lectura de archivos, detección de rotación |
| **Análisis** | `PostgreSqlLogParser`, `SqlTokenizer`, `NfaEngine` | Parsing, tokenización, detección de patrones |
| **Configuración** | `AppSettings`, `SettingsService` | Modelo de configuración, persistencia JSON |
| **Perfiles** | `NfaLoader`, `NFAModule.AutomatonProfile`, `NFA/*.json` | Definición y carga de reglas de detección |

---

## Componentes y responsabilidades

### FileWatcherLive

**Archivo:** `FileWatcherLive.cs`  
**Patrón:** Observador activo (polling). No usa `FileSystemWatcher` de .NET para evitar falsos negativos en entornos de red o rotación de archivos.

Responsabilidades:
- Buscar el archivo de log más reciente en `LogDirectory` que coincida con `WatchPattern`.
- Leer nuevas líneas desde la última posición leída (tail).
- Detectar rotación de archivo (el archivo actual tiene menos bytes que la última posición → nuevo archivo).
- Emitir evento `NewLines(IReadOnlyList<string>)` cada ciclo con las líneas nuevas.

Parámetros de construcción: `logDirectory`, `watchPattern`, `followRotation`.

### PostgreSqlLogParser

**Archivo:** `PostgreSqlLogParser.cs`  
**Patrón:** Parseador estático con regex pre-compiladas.

Tipos de línea reconocidos (`PgLogLineType`):
- `Statement` — línea `statement:` con la consulta SQL.
- `Duration` — línea `duration:` con tiempo en ms.
- `ConnectionReceived` — evento de conexión entrante con host.
- `ConnectionAuthorized` — evento de autenticación exitosa con usuario y base de datos.
- `Disconnection` — evento de cierre de conexión.
- `Error` / `Fatal` / `Warning` — eventos de severidad alta sin consulta SQL.

El método central `TryParse(string line)` devuelve un `PgLogEntry` con todos los campos extraídos o `null` si la línea no es reconocida.

### SqlTokenizer

**Archivo:** `SqlTokenizer.cs`  
**Patrón:** Máquina de estados de 4 fases (sin framework externo).

**Fase 1 — Normalización:**
- Fusión de comentarios de bloque (`/* ... */`) y de línea (`-- ...`).
- Decodificación de literales hexadecimales (`0x53454C454354` → `SELECT`).
- Decodificación de percent-encoding URL (`%53` → `S`).
- Decodificación de escapes unicode.
- Eliminación de dollar-quoting de PostgreSQL.

**Fase 2 — Detección de tautologías:**
- 5 patrones regex acotados detectan expresiones siempre-verdaderas.
- Sustituidas por el token marcador `__TAUTO__` → token `TAUTOLOGY` en el NFA.
- Ejemplos: `1=1`, `'a'='a'`, `x=x`, `1>0`, `1<>2`.

**Fase 3 — Escaneo (máquina de estados):**
- Identifica: identificadores, palabras clave SQL, números, strings, operadores.
- Lookup en diccionario de ~160 entradas para canonicalización.
- Ejemplos de canonicalización: `ILIKE` → `LIKE`, `PG_SLEEP` → `SLEEP`, `REPLICATION` → `SUPERUSER`.
- Resistente a ReDoS: no usa regex en esta fase.

**Fase 4 — Fusión:**
- Consolida secuencias multi-token en tokens compuestos canónicos:
  - `UNION ALL` → `UNION_ALL`
  - `INTO OUTFILE` → `INTO_OUTFILE`
  - `WAITFOR DELAY` → `WAITFOR_DELAY`

### NfaEngine

**Archivo:** `NfaEngine.cs`  
**Patrón:** Simulación powerset (Thompson NFA to DFA on-the-fly).

Algoritmo:
```
active = startStates
para cada token en tokens:
    next = startStates ∪ { delta[s][token] para s en active si delta[s][token] existe }
    active = next
    si active ∩ acceptStates ≠ ∅: retornar true
retornar false
```

Inyección de estados iniciales en cada token permite que el autómata detecte el patrón en cualquier posición de la secuencia (búsqueda de subcadena, no prefix-match).

Post-condición: si `RequireAbsentTokens` no está vacío, el match solo es válido si ninguno de esos tokens aparece en la entrada.

Complejidad: O(n × |estados|) donde n = cantidad de tokens.

### NfaLoader

**Archivo:** `NfaLoader.cs`  
**Patrón:** Factory estática.

- `LoadAll()` → `IReadOnlyList<NfaEngine>`: carga todos los `.json` de la carpeta `NFA/`, deserializa con `System.Text.Json`, construye `NfaEngine`.
- `LoadAllRaw()` → `IReadOnlyList<AutomatonProfile>`: misma operación pero devuelve los modelos crudos (usado por el gestor de módulos en UI).

### LogLiveWatcher

**Archivo:** `LogLiveWatcher.cs`  
**Patrón:** Orquestador pipeline, productor/consumidor con `Channel<string>`.

Responsabilidades:
- Suscribirse al evento `NewLines` de `FileWatcherLive`.
- Escribir líneas en `Channel<string>` (MPSC, sin límite).
- Task consumidora (única): leer del canal, parsear, correlacionar contexto de PID, tokenizar, ejecutar NFA engines en paralelo o secuencial, parear durations con statements.
- Gestionar ventana deslizante de brute-force por `user@host`.
- Emitir evento `EntryDetected(LogEntry)` al detectar amenaza o evento relevante.
- `ReloadEngines()`: swap atómico del array de engines con `Interlocked.Exchange`.
- `FlushStale()`: expulsar entradas de PID sin cierre explícito (limpieza de memoria).

**Correlación de contexto por PID:**
```
ConnectionReceived[pid]   → _pidHost[pid] = host
ConnectionAuthorized[pid] → _pidCtx[pid] = (user, db, host)
Statement[pid]            → lookup _pidCtx[pid] → llenar UserHost, Database
Duration[pid]             → parear con Statement pendiente → emitir LogEntry completo
Disconnection[pid]        → eliminar de _pidCtx, _pidHost, _pidPending
```

### MainWindow

**Archivos:** `MainWindow.xaml`, `MainWindow.xaml.cs`  
Implementa la UI completa:

- **Pestaña Monitor:** DataGrid con 9 columnas, filtros por texto y severidad.
- **Pestaña Dashboard:** 4 sparklines + distribución por nivel + top bases de datos + histograma de duraciones.
- **Pestaña Modules:** grid de tarjetas NFA con diagrama de estados ASCII y controles.
- **Pestaña Settings:** formularios de configuración vinculados a `AppSettings`.

Convertidores WPF implementados como clases anidadas:
- `LevelToSevColorConverter`, `LevelToBadgeFgConverter`, `LevelToBadgeBgConverter`, `LevelToBadgeBorderConverter`
- `BoolToInjTextConverter`, `BoolToInjFgConverter`, `BoolToInjBgConverter`, `BoolToInjBorderConverter`
- `DurFmtConverter`

### AppSettings / SettingsService

**Archivos:** `AppSettings.cs`, `SettingsService.cs`

- `AppSettings`: POCO con 20 propiedades.
- `SettingsService.Load()`: lee `%AppData%\LogGuardV2\settings.json`, deserializa con `System.Text.Json`.
- `SettingsService.Save(AppSettings)`: serializa y escribe, crea directorio si no existe.

---

## Flujo de datos

```
1. FileWatcherLive (Timer, 500ms)
   └─ Lee nuevas líneas desde posición guardada
   └─ Detecta rotación de archivo
   └─ Emite evento NewLines(IReadOnlyList<string>)

2. LogLiveWatcher.OnNewLines (handler en timer thread)
   └─ Agrega líneas a buffer de líneas parciales (multi-line PostgreSQL)
   └─ Escribe líneas completas en Channel<string>.Writer

3. ConsumeEntries (Task.Run, consumer único)
   └─ Lee línea del Channel
   └─ PostgreSqlLogParser.TryParse(line) → PgLogEntry
   └─ Actualiza contexto de PID (_pidCtx, _pidHost, _pidPending)
   └─ Si es Statement:
       └─ SqlTokenizer.Tokenize(query) → List<string>
       └─ RunEngines(tokens) → threat type o null
           └─ Para cada NfaEngine en paralelo/secuencial:
               └─ NfaEngine.Run(tokens) → bool
       └─ Si brute-force: evaluar ventana deslizante
   └─ Si es Duration: parear con Statement pendiente
   └─ Construir LogEntry
   └─ Actualizar contadores atómicos (Interlocked)
   └─ Emitir EntryDetected(LogEntry)

4. MainWindow.OnLiveEntry (Dispatcher.InvokeAsync)
   └─ Insertar LogEntry en ObservableCollection
   └─ Aplicar filtros activos
   └─ Actualizar KPI bar
   └─ Actualizar sparkline buffers

5. DispatcherTimer (1s)
   └─ Calcular métricas del segundo (reset Interlocked counters)
   └─ Actualizar KPI labels
   └─ Redraw sparklines en Canvas
   └─ Actualizar uptime
```

---

## Patrones de diseño identificados

| Patrón | Implementación |
|--------|----------------|
| **Observer** | Eventos `NewLines` (FileWatcherLive → LogLiveWatcher) y `EntryDetected` (LogLiveWatcher → MainWindow) |
| **Pipeline** | Cadena: FileWatcher → Channel → Parser → Tokenizer → NfaEngine → UI |
| **Producer/Consumer** | `Channel<string>` MPSC entre timer thread y consumer task |
| **Strategy** | Array de `NfaEngine` intercambiables; hot reload con `Interlocked.Exchange` |
| **Factory estática** | `NfaLoader.LoadAll()` construye engines desde JSON |
| **MVVM parcial** | `AppSettings` como model, binding WPF en Settings tab; código-behind en MainWindow para el resto |
| **Value Object** | `LogEntry` inmutable (campos readonly, construido de una vez) |
| **Flyweight** | Perfiles NFA compartidos; engines instanciados una vez y reutilizados por referencia |
| **State Machine** | `SqlTokenizer` fases 1 y 3 implementadas como máquinas de estado explícitas |
| **Null Object** | `TryParse()` devuelve `null` para líneas no reconocidas sin lanzar excepción |

---

## Interfaces y contratos relevantes

### Evento NewLines

```csharp
// FileWatcherLive
public event Action<IReadOnlyList<string>>? NewLines;
```

### Evento EntryDetected

```csharp
// LogLiveWatcher
public event Action<LogEntry>? EntryDetected;
```

### Contrato NfaEngine

```csharp
// NfaEngine
public bool Run(IReadOnlyList<string> tokens);
```

### Contrato PostgreSqlLogParser

```csharp
// PostgreSqlLogParser (static)
public static PgLogEntry? TryParse(string line);
public static bool LooksLikeHeader(string line);
public static DateTimeOffset? ResolveTimestamp(string raw, string timezone);
```

### Contrato SqlTokenizer

```csharp
// SqlTokenizer (static)
public static List<string> Tokenize(string sql);
```

### Contrato SettingsService

```csharp
// SettingsService (static)
public static AppSettings Load();
public static void Save(AppSettings settings);
```

### Esquema JSON de perfil NFA

```json
{
  "id": "string",
  "target": {
    "engine": "postgresql",
    "version_min": "string"
  },
  "alphabet": ["string"],
  "states": [
    { "id": "string", "is_start": true, "is_accept": false }
  ],
  "transitions": [
    { "from": "string", "symbol": "string", "to": "string" }
  ],
  "require_absent_tokens": ["string"],
  "metadata": {
    "severity": "Critical|High|Medium|Low",
    "description": "string",
    "tags": ["string"]
  }
}
```

---

## Variables de entorno y configuración

No se usan variables de entorno. La configuración es completamente gestionada por `AppSettings` / `SettingsService`.

**Ruta del archivo de configuración:**
```
%AppData%\LogGuardV2\settings.json
```
En Windows típicamente: `C:\Users\<usuario>\AppData\Roaming\LogGuardV2\settings.json`

**Ruta de perfiles NFA:**
```
<directorio_del_ejecutable>\NFA\*.json
```

> **Nota:** No hay flags de entorno, variables de compilación condicionales ni feature flags en el código fuente verificado.

---

## Modelo de datos NFA

### AutomatonProfile (NFAModule.cs)

```
AutomatonProfile
├── Id: string
├── Target: TargetDefinition
│   ├── Engine: string          ("postgresql")
│   └── VersionMin: string      (ej. "12.0")
├── Alphabet: string[]          (tokens válidos para este autómata)
├── States: StateDefinition[]
│   ├── Id: string              (nombre del estado, ej. "q0", "q_sqli")
│   ├── IsStart: bool
│   └── IsAccept: bool
├── Transitions: TransitionDefinition[]
│   ├── From: string            (estado origen)
│   ├── Symbol: string          (token que dispara la transición)
│   └── To: string              (estado destino)
├── RequireAbsentTokens: string[]  (tokens cuya presencia invalida el match)
└── Metadata: MetadataDefinition
    ├── Severity: string        ("Critical", "High", "Medium", "Low")
    ├── Description: string
    └── Tags: string[]
```

### LogEntry (LogEntry.cs)

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `Timestamp` | `DateTimeOffset` | Timestamp del evento normalizado |
| `Pid` | `int` | Process ID de la conexión PostgreSQL |
| `Level` | `string` | Severidad (FATAL/ERROR/WARN/INFO/DEBUG/LOG) |
| `UserHost` | `string` | Formato `usuario@host` |
| `Database` | `string` | Nombre de la base de datos |
| `Query` | `string` | Consulta SQL ejecutada |
| `Duration` | `double` | Duración en milisegundos |
| `IsInjected` | `bool` | True si algún NFA detectó amenaza |
| `ThreatType` | `string?` | Tipo de amenaza detectada (`SQLI`, `BRUTEFORCE`, etc.) |

---

## Concurrencia y sincronización

### Hilos activos

| Hilo / Tarea | Origen | Accede a | Sincronización |
|---|---|---|---|
| **UI Thread** | WPF Dispatcher | `ObservableCollection<LogEntry>`, controles UI, KPI labels | `Dispatcher.InvokeAsync` para accesos desde otros hilos |
| **Timer Thread** | `System.Threading.Timer` (FileWatcherLive) | `_readLock`, `_pendingLine` | `lock (_readLock)` |
| **Consumer Task** | `Task.Run` (LogLiveWatcher) | `_pidCtx`, `_pidHost`, `_pidPending`, `_bfWindow`, `Channel.Reader` | Acceso exclusivo: `Channel<string>` con `SingleReader=true` |
| **DispatcherTimer** | WPF (UI thread) | Contadores `Interlocked`, sparkline buffers | `Interlocked.Read/Exchange` para contadores |

### Primitivas de sincronización

| Primitiva | Propósito | Campos protegidos |
|-----------|-----------|-------------------|
| `Interlocked` (long) | Contadores de métricas sin lock | `_totalEvents`, `_fatalErrorCount`, `_injectedCount`, `_durationSumUs`, `_durationCount`, `_eventsThisSecond`, `_injectedThisSecond`, `_fatalThisSecond` |
| `Interlocked.Exchange` (reference) | Hot reload de engines | `_engines` (array de NfaEngine) |
| `lock (_fatalWindowLock)` | Cola de ventana de fatales | `_fatalMinWindow` (Queue<DateTime>) |
| `Channel<string>` MPSC sin límite | Desacoplar productor (timer) de consumidor | Líneas de log entre FileWatcherLive y ConsumeEntries |

---

## Métricas y KPI en tiempo real

Actualizadas cada 1 segundo por `DispatcherTimer`:

| Métrica | Cálculo | Retención |
|---------|---------|-----------|
| **Events/s** | `_eventsThisSecond` (reset Interlocked cada tick) | 1 punto/s |
| **Fatal/Error count** | Conteo en `_fatalMinWindow` con TTL 60 s (cola deslizante) | Ventana 60 s |
| **Injected/s** | `_injectedThisSecond` (reset Interlocked cada tick) | 1 punto/s |
| **Avg Duration** | `_durationSumUs / _durationCount` (precisión microsegundos) | Acumulado desde inicio |
| **Uptime** | `DateTime.UtcNow - _appStart` | Desde inicio de la aplicación |

**Sparklines:** 4 buffers de 48 puntos, 1 s cada uno — Events/s, Injected/s, Fatal/s, Avg Duration. Renderizados como gráficos de línea + área sobre `Canvas` WPF.

---

## Perfiles de detección incluidos

| Perfil | ID | Amenaza | Severidad | Estados | Técnica de detección |
|--------|----|----|---|--------|----------|
| SQL_Injection.json | `pgsql-sqli-v2` | SQLI | High | 10 | Tautología, UNION/UNION_ALL, SLEEP, INFORMATION_SCHEMA, bypass OR |
| Brute_Force.json | `pgsql-bruteforce-v1` | BRUTEFORCE | Medium | 8 | Patrón SELECT+WHERE + ventana deslizante ≥5 en 60 s |
| Exfiltration.json | `pgsql-exfil-v1` | EXFIL | High | 5 | SELECT */cols FROM tabla SIN WHERE ni LIMIT |
| Privilege Escalation.json | `pgsql-privesc-v1` | PRIVESC | Critical | 6 | ALTER USER/ROLE ... SUPERUSER |
| Enumeration.json | `pgsql-discovery-v2` | DISCOVERY | Medium | 4 | Acceso directo a information_schema, pg_shadow, pg_user, pg_roles |
| Time SQI.json | `pgsql-time-sqli-v2` | SQLI | High | 5 | SLEEP(), pg_sleep(), BENCHMARK() |

---

## Rendimiento y complejidad algorítmica

| Operación | Latencia típica | Complejidad |
|-----------|----------------|-------------|
| Ciclo de polling de archivo | ~0 ms (inactivo) | O(1) |
| Parse de línea de log | < 0.1 ms | Regex pre-compilada, entrada acotada |
| Tokenización SQL | < 0.5 ms | O(n), n = longitud SQL |
| Match NFA por engine | < 0.3 ms | O(tokens × estados) |
| Pipeline end-to-end | < 5 ms | Dominado por scheduling del Channel |
| Inserción en DataGrid | < 1 ms | `ObservableCollection.Insert(0, entry)` |

**Uso de memoria:**
- Buffer DataGrid: ~2 MB (5,000 entradas máximo).
- Tablas de estado NFA: < 1 KB por engine.
- Diccionarios por PID: acotados por número de conexiones concurrentes.
- Ventanas de brute-force: máx. 1 entrada por usuario@host (TTL 60 s).
