# LogGuardV2

Sistema de monitoreo y detección de amenazas en tiempo real para bases de datos PostgreSQL. Aplicación de escritorio Windows (WPF / .NET 10) que analiza logs de PostgreSQL mediante autómatas finitos no deterministas (NFA) para identificar ataques SQL activos sin agentes ni modificaciones en el servidor.

---

## Índice

- [Descripción general](#descripción-general)
- [Funcionalidades principales](#funcionalidades-principales)
- [Requisitos previos](#requisitos-previos)
- [Instalación](#instalación)
- [Configuración](#configuración)
- [Uso](#uso)
- [Estructura de carpetas](#estructura-de-carpetas)
- [Dependencias](#dependencias)
- [Guía de desarrollo](#guía-de-desarrollo)

---

## Descripción general

LogGuardV2 lee los archivos de log generados por PostgreSQL, parsea cada línea con un motor especializado, tokeniza el SQL extraído en una cadena de 4 fases y lo evalúa contra un conjunto de perfiles NFA (autómatas) que representan patrones de ataque conocidos. Los resultados se muestran en tiempo real en una interfaz gráfica con métricas, filtros y paneles de análisis.

**Principios de diseño:**
- Sin agentes externos ni modificaciones al servidor PostgreSQL.
- Sin dependencias NuGet — solo bibliotecas integradas de .NET 10.
- Detección sub-milisegundo mediante autómatas de estado finito.
- Arquitectura orientada a eventos con canal productor/consumidor desacoplado.

---

## Funcionalidades principales

| Categoría | Detalle |
|-----------|---------|
| **Monitoreo en tiempo real** | Polling de archivos de log cada 500 ms con detección de rotación |
| **Detección de amenazas** | 6 perfiles NFA: SQL Injection, Brute Force, Exfiltración, Escalación de privilegios, Enumeración, Time-based SQLi |
| **Tokenizador SQL** | Pipeline de 4 fases resistente a técnicas de evasión (comentarios, hex, URL-encoding, tautologías) |
| **Correlación de sesiones** | Contexto por PID: usuario, host, base de datos correlacionados entre eventos de conexión y consulta |
| **Panel de métricas (KPI)** | Eventos/s, conteo Fatal/Error, Inyecciones/s, Duración promedio, Uptime — actualizados cada 1 s |
| **Sparklines** | Gráficos históricos de 48 puntos para cada métrica principal |
| **Módulos recargables en caliente** | Perfiles NFA recargables sin reiniciar la aplicación |
| **Filtros interactivos** | Búsqueda de texto + chips de severidad (FATAL, ERROR, WARN, INFO, DEBUG, LOG) |
| **Persistencia de configuración** | Ajustes guardados en `%AppData%\LogGuardV2\settings.json` |

---

## Requisitos previos

### Sistema operativo
- Windows 10 / 11 (x64)

### Runtime
- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (Windows)

### PostgreSQL — configuración requerida

El servidor PostgreSQL debe tener en `postgresql.conf`:

```ini
log_destination = 'stderr'
logging_collector = on
log_statement = 'all'
log_duration = on
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %q%u@%h %d '
```

> **Importante:** El formato exacto de `log_line_prefix` es requerido. El parser espera: `[timestamp] [pid] [usuario@host] [database]`.

---

## Instalación

### Desde código fuente

```bash
# Clonar el repositorio
git clone https://github.com/usuario/LogGuardV2.git
cd LogGuardV2

# Compilar
dotnet build LogGuardV2.csproj -c Release

# Ejecutar
dotnet run --project LogGuardV2.csproj
```

### Compilar ejecutable autónomo

```bash
dotnet publish LogGuardV2.csproj -c Release -r win-x64 --self-contained true -o publish/
```

El ejecutable resultante estará en `publish/LogGuardV2.exe`.

---

## Configuración

### Interfaz gráfica — pestaña Settings

#### Fuente y monitoreo

| Parámetro | Descripción | Valor por defecto |
|-----------|-------------|-------------------|
| `LogDirectory` | Ruta al directorio de logs de PostgreSQL | `""` |
| `WatchPattern` | Patrón glob para archivos (ej. `*.log`) | `"*.log"` |
| `Timezone` | Zona horaria para normalizar timestamps | Local del sistema |
| `LogLineFormat` | Formato esperado de `log_line_prefix` | Estándar PostgreSQL |
| `FollowRotation` | Detectar y seguir rotación de archivos | `true` |
| `ReplayOnStart` | Releer el archivo completo al arrancar | `false` |

#### Parser

| Parámetro | Descripción |
|-----------|-------------|
| `ParseCoreFields` | Extraer campos básicos (nivel, pid, timestamp) |
| `ParseConnectionDetails` | Extraer usuario, host, base de datos |
| `ParseQueryDetails` | Extraer query y duración |
| `ParseSystemMetrics` | Extraer métricas del sistema |
| `ParseRawMessage` | Preservar mensaje en bruto |
| `RedactPasswords` | Redactar contraseñas detectadas en los logs |

#### Alertas

| Parámetro | Descripción |
|-----------|-------------|
| `AlertWebhookUrl` | URL de webhook para notificaciones externas |
| `AlertMinLevel` | Nivel mínimo de severidad para disparar alerta |
| `DesktopNotifications` | Activar notificaciones de escritorio Windows |
| `AudioBeepOnFatal` | Emitir beep en eventos FATAL |

### Edición manual del archivo de configuración

`%AppData%\LogGuardV2\settings.json` se crea automáticamente en el primer arranque. Puede editarse con cualquier editor de texto.

---

## Uso

### Flujo básico

1. Abrir LogGuardV2.
2. Ir a pestaña **Settings** → configurar `LogDirectory` con la ruta de logs de PostgreSQL.
3. Volver a pestaña **Monitor** → presionar **Start**.
4. Las entradas aparecen en el DataGrid en tiempo real.

### Interpretar el DataGrid

| Columna | Descripción |
|---------|-------------|
| Timestamp | Fecha y hora del evento |
| PID | Process ID de la conexión PostgreSQL |
| Level | Severidad: FATAL / ERROR / WARN / INFO / DEBUG / LOG |
| User@Host | Usuario y host de origen de la conexión |
| Database | Base de datos afectada |
| Query | Consulta SQL ejecutada |
| Duration | Duración de ejecución en milisegundos |
| Injected | Indicador visual si se detectó inyección SQL |
| Threat | Tipo de amenaza: `SQLI`, `BRUTEFORCE`, `EXFIL`, `PRIVESC`, `DISCOVERY` |

### Filtrar entradas

- **Búsqueda de texto:** filtro en tiempo real por Query, Usuario y Base de datos.
- **Chips de severidad:** activar/desactivar cada nivel de log individualmente.

### Panel Dashboard

Sparklines históricos (48 puntos, 1 s cada uno) para Events/s, Injected/s, Fatal/s y Avg Duration. Incluye distribución por severidad, top 5 bases de datos más activas e histograma de duraciones.

### Gestor de módulos

Pestaña **Modules** — muestra todos los perfiles NFA cargados con diagrama de estados, descripción y controles de activación. Botón **Reload** recarga todos los archivos JSON desde disco sin reiniciar la aplicación.

---

## Estructura de carpetas

```
LogGuardV2/
├── App.xaml                        # Recursos globales WPF (colores, estilos, convertidores)
├── App.xaml.cs                     # Clase Application
├── AppSettings.cs                  # Modelo de configuración (20 propiedades)
├── AssemblyInfo.cs                 # Metadatos de ensamblado WPF
├── FileWatcherLive.cs              # Polling de archivos de log (500 ms)
├── LogEntry.cs                     # Modelo de fila para DataGrid
├── LogGuardV2.csproj               # Proyecto .NET 10 WPF
├── LogGuardV2.slnx                 # Solución Visual Studio
├── LOGOGUARD.ico                   # Ícono de la aplicación
├── LogLiveWatcher.cs               # Orquestador del pipeline de análisis
├── MainWindow.xaml                 # Definición UI (~900 líneas XAML)
├── MainWindow.xaml.cs              # Code-behind UI (~1230 líneas C#)
├── NFAModule.cs                    # Modelo de datos de perfiles NFA
├── NfaEngine.cs                    # Motor NFA (simulación powerset)
├── NfaLoader.cs                    # Carga y deserialización de perfiles JSON
├── PostgreSqlLogParser.cs          # Parser de líneas de log PostgreSQL
├── SettingsService.cs              # Persistencia de configuración JSON
├── SqlTokenizer.cs                 # Tokenizador SQL de 4 fases
│
├── NFA/                            # Perfiles de detección (autómatas JSON)
│   ├── SQL_Injection.json          # Tautología, UNION, SLEEP, INFORMATION_SCHEMA
│   ├── Brute_Force.json            # Ventana deslizante 5 intentos / 60 s
│   ├── Exfiltration.json           # SELECT sin WHERE ni LIMIT
│   ├── Privilege Escalation.json   # ALTER USER/ROLE ... SUPERUSER
│   ├── Enumeration.json            # Acceso a tablas de sistema
│   └── Time SQI.json               # pg_sleep(), BENCHMARK(), SLEEP()
│
└── docs/
    └── assets/                     # Diagramas SVG
        ├── architecture-overview.svg
        ├── pipeline.svg
        ├── tokenizer-pipeline.svg
        └── nfa-*.svg               # Diagrama por cada perfil NFA
```

---

## Dependencias

Sin dependencias NuGet externas. Solo bibliotecas integradas de .NET:

| Biblioteca | Uso |
|------------|-----|
| `System.Windows` (WPF) | UI, controles XAML, Dispatcher |
| `System.Text.Json` | Serialización de configuración y perfiles NFA |
| `System.Threading.Channels` | Canal productor/consumidor desacoplado |
| `System.Text.RegularExpressions` | Regex pre-compiladas para parsing y detección de tautologías |

---

## Guía de desarrollo

### Configurar entorno

```bash
# Requisitos: .NET 10 SDK + Visual Studio 2022 o VS Code con extensión C#

dotnet restore
dotnet build
dotnet run --project LogGuardV2.csproj
```

### Agregar un nuevo perfil de detección NFA

1. Crear archivo `.json` en `NFA/` con el esquema `AutomatonProfile`:

```json
{
  "id": "pgsql-mi-amenaza-v1",
  "target": { "engine": "postgresql", "version_min": "12.0" },
  "alphabet": ["SELECT", "TOKEN_A", "TOKEN_B"],
  "states": [
    { "id": "q0", "is_start": true, "is_accept": false },
    { "id": "q_accept", "is_start": false, "is_accept": true }
  ],
  "transitions": [
    { "from": "q0", "symbol": "TOKEN_A", "to": "q_accept" }
  ],
  "require_absent_tokens": [],
  "metadata": {
    "severity": "High",
    "description": "Descripción de la amenaza",
    "tags": ["custom"]
  }
}
```

2. En la pestaña **Modules** presionar **Reload** — recarga en caliente.

### Agregar un nuevo token SQL

Editar el diccionario de ~160 entradas en `SqlTokenizer.cs`:

```csharp
{ "NUEVA_FUNCION", "TOKEN_CANONICO" },
```

### Agregar un nuevo tipo de línea de log

1. Agregar entrada al enum `PgLogLineType` en `PostgreSqlLogParser.cs`.
2. Implementar lógica de extracción en `TryParse()`.
3. Manejar el nuevo tipo en `LogLiveWatcher.ProcessLine()`.

### Convenciones de código

- Una clase por archivo, nombre de archivo igual al nombre de clase.
- Convertidores WPF como clases anidadas en `MainWindow.xaml.cs`.
- `Interlocked` para todos los contadores compartidos entre hilos.
- `Channel<string>` sin límite, modo MPSC (múltiples productores, consumidor único).
- Sin comentarios de código salvo cuando el motivo no es obvio por el código mismo.
