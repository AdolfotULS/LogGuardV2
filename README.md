# LogGuard V2

> **Real-time PostgreSQL threat detection via NFA-driven log analysis**

LogGuard V2 is a Windows WPF desktop application that monitors PostgreSQL database logs in real time, tokenizes SQL queries, and runs them through configurable Non-deterministic Finite Automata (NFA) to detect SQL injection, brute-force attacks, privilege escalation, data exfiltration, and schema enumeration — with sub-millisecond pattern-matching latency.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Folder Structure](#folder-structure)
- [Core Components](#core-components)
  - [FileWatcherLive](#filewatcherlive)
  - [LogLiveWatcher](#livelogwatcher)
  - [PostgreSqlLogParser](#postgresqllogparser)
  - [SqlTokenizer](#sqltokenizer)
  - [NfaEngine](#nfaengine)
  - [NfaLoader](#nfaloader)
- [Data Models](#data-models)
  - [LogEntry](#logentry)
  - [NFAModule](#nfamodule)
  - [AppSettings](#appsettings)
- [NFA Automata System](#nfa-automata-system)
  - [JSON Schema Reference](#json-schema-reference)
  - [State and Transition Structure](#state-and-transition-structure)
  - [How the Engine Loads and Executes Automata](#how-the-engine-loads-and-executes-automata)
  - [Built-in Threat Profiles](#built-in-threat-profiles)
- [Processing Pipeline](#processing-pipeline)
  - [Full Pipeline Diagram](#full-pipeline-diagram)
  - [Multi-line Entry Buffering](#multi-line-entry-buffering)
  - [PID Context Correlation](#pid-context-correlation)
  - [Duration Pairing](#duration-pairing)
  - [Brute-Force Sliding Window](#brute-force-sliding-window)
- [SQL Tokenizer Deep Dive](#sql-tokenizer-deep-dive)
  - [Phase 1 — Normalization](#phase-1--normalization)
  - [Phase 2 — Tautology Annotation](#phase-2--tautology-annotation)
  - [Phase 3 — State-Machine Scanner](#phase-3--state-machine-scanner)
  - [Phase 4 — Multi-word Fusion](#phase-4--multi-word-fusion)
  - [Token Reference Table](#token-reference-table)
  - [Evasion Resistance](#evasion-resistance)
- [Threading and Concurrency](#threading-and-concurrency)
- [Real-time Detection System](#real-time-detection-system)
- [Alert System](#alert-system)
- [UI Architecture](#ui-architecture)
  - [Threat Monitor Tab](#threat-monitor-tab)
  - [Dashboard Tab](#dashboard-tab)
  - [Module Manager Tab](#module-manager-tab)
  - [Settings Tab](#settings-tab)
- [Configuration](#configuration)
- [Examples](#examples)
  - [Detection Examples](#detection-examples)
  - [Tokenization Examples](#tokenization-examples)
  - [Automaton Trace Examples](#automaton-trace-examples)
  - [Log Line Parsing Examples](#log-line-parsing-examples)
- [Adding New Detection Rules](#adding-new-detection-rules)
  - [Writing a New NFA Profile](#writing-a-new-nfa-profile)
  - [Extending the Tokenizer](#extending-the-tokenizer)
  - [Adding New Log Line Types](#adding-new-log-line-types)
- [Performance](#performance)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Dependencies](#dependencies)
- [Future Extensions](#future-extensions)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        LogGuard V2                              │
│                                                                 │
│  ┌──────────────┐    ┌──────────────────────────────────────┐   │
│  │  WPF UI      │    │         LogLiveWatcher               │   │
│  │  (UI Thread) │◄───│  (Consumer Task + Producer Thread)   │   │
│  └──────┬───────┘    └──────────────────┬───────────────────┘   │
│         │                               │                        │
│  ┌──────▼───────┐              ┌────────▼────────┐              │
│  │ MainWindow   │              │ FileWatcherLive  │              │
│  │ KPI / Charts │              │ (500ms poll)     │              │
│  │ DataGrid     │              └────────┬─────────┘              │
│  └──────────────┘                       │ NewLines event         │
│                               ┌─────────▼──────────┐            │
│                               │  Channel<string>    │            │
│                               │  (unbounded MPSC)   │            │
│                               └─────────┬───────────┘            │
│                                         │ async reader           │
│                               ┌─────────▼──────────┐            │
│                               │ PostgreSqlLogParser │            │
│                               └─────────┬───────────┘            │
│                                         │ PgLogEntry             │
│                               ┌─────────▼──────────┐            │
│                               │   SqlTokenizer      │            │
│                               │   (4-phase pipeline)│            │
│                               └─────────┬───────────┘            │
│                                         │ List<string>           │
│                               ┌─────────▼──────────┐            │
│                               │   NfaEngine[]       │            │
│                               │   (parallel/seq)    │            │
│                               └─────────┬───────────┘            │
│                                         │ LogEntry               │
│                               ┌─────────▼──────────┐            │
│                               │  EntryDetected evt  │            │
│                               └────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

![Architecture Overview](docs/assets/architecture-overview.svg)

**Design Principles:**
- File I/O decoupled from analysis via `Channel<string>` (producer/consumer)
- All NFA state is read-only after construction — zero locking during matching
- Tokenizer uses state-machine scan (no regex in hot path) — immune to ReDoS
- Engine list swapped atomically via `Interlocked.Exchange` for hot reload
- UI thread never blocks on I/O or computation

---

## Folder Structure

```
LogGuardV2/
├── App.xaml                    WPF application entry point and global resource dictionary
├── App.xaml.cs                 Application class
├── AppSettings.cs              Configuration model (20 properties)
├── AssemblyInfo.cs             Assembly metadata
├── MainWindow.xaml             Full UI definition (4 tabs, custom chrome)
├── MainWindow.xaml.cs          ~1230-line UI code-behind
├── SettingsService.cs          JSON settings persistence to %AppData%
├── LogGuardV2.csproj           Project file (net10.0-windows, WPF)
├── LOGOGUARD.ico               Application icon
│
├── src/
│   ├── Engine/
│   │   ├── FileWatcherLive.cs      Polling-based log file tail with rotation support
│   │   ├── LogLiveWatcher.cs       Pipeline orchestrator (parser → tokenizer → NFA)
│   │   ├── NfaEngine.cs            Substring NFA matcher
│   │   ├── NfaLoader.cs            NFA JSON deserializer
│   │   ├── PostgreSqlLogParser.cs  PostgreSQL log line parser (7 line types)
│   │   └── SqlTokenizer.cs         4-phase SQL normalizer and tokenizer
│   └── Model/
│       ├── LogEntry.cs             Display model for DataGrid rows
│       └── NFAModule.cs            Automaton definition (profile + states + transitions)
│
└── NFA/                        Threat detection profiles (JSON automata)
    ├── Brute_Force.json
    ├── Enumeration.json
    ├── Exfiltration.json
    ├── Privilege Escalation.json
    ├── SQL_Injection.json
    └── Time SQI.json
```

---

## Core Components

### FileWatcherLive

**File:** [`src/Engine/FileWatcherLive.cs`](src/Engine/FileWatcherLive.cs)

Polls the newest matching log file every 500 ms and emits new lines via `NewLines` event. Uses a persistent `FileStream` rather than repeated open/close to avoid NTFS buffering issues common with `FileSystemWatcher` on Windows.

```
public sealed class FileWatcherLive : IDisposable
{
    public event Action<IReadOnlyList<string>>? NewLines;

    public FileWatcherLive(string directory, string pattern, bool followRotation)
    public void Start(bool replayFromStart)
    public void Stop()
    public void Dispose()
}
```

**Rotation detection:** On each poll, the watcher checks whether the latest file matching `pattern` has changed. If a newer file appears (log rotation), it reopens the stream from the beginning of the new file.

**Startup modes:**
- `replayFromStart = false` — seeks to EOF, monitors only new lines
- `replayFromStart = true` — seeks to BOF, replays entire file through the pipeline

**Error resilience:** Any read exception causes the stream to be disposed and reopened on the next poll cycle. The watcher never terminates due to transient file-lock errors.

---

### LogLiveWatcher

**File:** [`src/Engine/LogLiveWatcher.cs`](src/Engine/LogLiveWatcher.cs)

Orchestrates the entire detection pipeline. Decouples file I/O from CPU-heavy analysis using a `Channel<string>`.

```
internal sealed class LogLiveWatcher : IDisposable
{
    public int EngineCount => _engines.Count;
    public event Action<LogEntry>? EntryDetected;

    public LogLiveWatcher(AppSettings settings, string nfaFolder)
    public void Start(bool replayFromStart = false)
    public void ReloadEngines()        // hot reload — atomic swap
    public void FlushStale(long maxAgeMs = 2000)
    public void Dispose()
}
```

**Internal state dictionaries** (consumer-task-only, no locking needed):

| Dictionary | Key | Value | Purpose |
|---|---|---|---|
| `_pidCtx` | PID | `(User, Database, Host)` | Resolved connection context |
| `_pidHost` | PID | Host string | Staged from `ConnectionReceived` |
| `_pidPending` | PID | `(LogEntry, CreatedTick)` | Statement awaiting Duration |
| `_bfWindow` | `user@host` | `Queue<DateTimeOffset>` | Brute-force sliding window |

**Channel configuration:**
```csharp
Channel.CreateUnbounded<string>(new UnboundedChannelOptions
{
    SingleReader                  = true,   // only consumer task reads
    SingleWriter                  = false,  // file-watcher + UI FlushStale both write
    AllowSynchronousContinuations = false   // prevents reader running inline on writer
});
```

---

### PostgreSqlLogParser

**File:** [`src/Engine/PostgreSqlLogParser.cs`](src/Engine/PostgreSqlLogParser.cs)

Parses PostgreSQL log lines into typed `PgLogEntry` objects. Supports 7 log line types distinguished by message prefix.

```
public enum PgLogLineType
{
    Unknown, General, Statement, Duration,
    ConnectionReceived, ConnectionAuthenticated,
    ConnectionAuthorized, Disconnection
}
```

**Header pattern** (compiled, CultureInvariant):
```
^(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+
 (?<tz>\S+)\s+\[(?<pid>\d+)\]\s+(?<severity>[A-Z]+):\s{1,}
 (?<message>[\s\S]*)$
```

**Timezone resolution priority:**
1. Literal `UTC`
2. `±HH:MM` offset string
3. IANA / Windows timezone name via `TimeZoneInfo.TryFindSystemTimeZoneById`
4. Fallback: treat as UTC (entry preserved, never dropped)

**Per-type regex patterns:**

| Type | Regex Summary |
|---|---|
| `Statement` | `^statement:\s*(?<statement>...)$` |
| `Duration` | `^duration:\s*(?<duration_ms>\d+(?:\.\d+)?)\s+ms...` |
| `ConnectionReceived` | `^connection received:\s+host=(?<host>\S+)...` |
| `ConnectionAuthenticated` | `^connection authenticated:\s+identity="..."...` |
| `ConnectionAuthorized` | `^connection authorized:\s+user=... database=...` |
| `Disconnection` | `^disconnection:\s+session time:...` |

---

### SqlTokenizer

**File:** [`src/Engine/SqlTokenizer.cs`](src/Engine/SqlTokenizer.cs)

Converts raw SQL into a canonical token sequence via a four-phase pipeline. The hot path (Phase 3) uses a hand-written state machine — no regex — making it immune to ReDoS regardless of input length or content.

```
public static class SqlTokenizer
{
    public static List<string> Tokenize(string sql)
}
```

Thread-safe: all state is static read-only after startup. See [SQL Tokenizer Deep Dive](#sql-tokenizer-deep-dive) for full documentation.

---

### NfaEngine

**File:** [`src/Engine/NfaEngine.cs`](src/Engine/NfaEngine.cs)

Runs substring NFA matching on a pre-materialized token list. Implements the powerset simulation algorithm with start-state re-injection at each step to find matches anywhere in the token stream (not just full-string).

```
public sealed class NfaEngine
{
    public string ProfileId   { get; }
    public string ProfileName { get; }
    public string ThreatType  { get; }
    public string Severity    { get; }
    public IReadOnlyList<string> RequireAbsentTokens { get; }

    public NfaEngine(NFAModule.AutomatonProfile profile)
    public bool Run(IReadOnlyList<string> tokens)
}
```

**Internal tables:**
```
_startStates  : HashSet<string>                                    — start state IDs
_acceptStates : HashSet<string>                                    — accept state IDs
_delta        : Dictionary<string, Dictionary<string, List<string>>> — [from][symbol] = [tos]
```

**Algorithm:**
```csharp
var active = new HashSet<string>(_startStates);
var next   = new HashSet<string>(...);

for each token in tokens:
    next = _startStates ∪ { delta[s][token] for s in active }
    swap(active, next)
    if active ∩ _acceptStates ≠ ∅: return true

return false
```

**Complexity:** O(n × s) where n = token count, s = state count. Typical execution: < 0.5 ms per query.

---

### NfaLoader

**File:** [`src/Engine/NfaLoader.cs`](src/Engine/NfaLoader.cs)

Deserializes NFA profiles from JSON files in the `NFA/` folder.

```
public static class NfaLoader
{
    // Returns NfaEngine for each enabled profile; skips malformed files silently
    public static List<NfaEngine> LoadAll(string folder)

    // Returns all profiles (enabled + disabled) with file paths; used by Module Manager UI
    public static List<(NFAModule.AutomatonProfile Profile, string FilePath)> LoadAllRaw(string folder)
}
```

Uses case-insensitive JSON deserialization. Malformed or unreadable files are skipped — the engine list is never null.

---

## Data Models

### LogEntry

**File:** [`src/Model/LogEntry.cs`](src/Model/LogEntry.cs)

The display model bound to the DataGrid. Created by `LogLiveWatcher` after PID correlation and NFA matching.

```csharp
public class LogEntry
{
    public string Timestamp  { get; set; }  // "yyyy-MM-dd HH:mm:ss.fff UTC"
    public int    Pid        { get; set; }  // PostgreSQL process ID
    public string Level      { get; set; }  // Severity (CRITICAL/HIGH/MEDIUM/LOW/WARNING/LOG)
    public string UserHost   { get; set; }  // "user@host" from PID context
    public string Database   { get; set; }  // Database name from PID context
    public string Query      { get; set; }  // Raw SQL statement text
    public double Duration   { get; set; }  // Execution time in ms (from Duration line)
    public bool   IsInjected { get; set; }  // True if any NFA matched
    public string ThreatType { get; set; }  // "SQLI" / "BRUTEFORCE" / "EXFIL" / etc.
}
```

---

### NFAModule

**File:** [`src/Model/NFAModule.cs`](src/Model/NFAModule.cs)

Container for NFA automaton definitions. Nested classes map directly to the JSON profile schema.

```
NFAModule
└── AutomatonProfile (sealed)
    ├── string ProfileId
    ├── string Name
    ├── string Version
    ├── bool   Enabled
    ├── string ThreatType          — SQLI | BRUTEFORCE | EXFIL | PRIVESC | DISCOVERY
    ├── TargetDefinition Target
    │   ├── string Source          — "PostgreSQL"
    │   ├── string InputField      — "Query"
    │   └── string Tokenizer       — "SqlTokenizer"
    ├── List<string> Alphabet
    ├── List<StateDefinition> States
    │   ├── string Id
    │   ├── bool   IsStart
    │   └── bool   IsAccept
    ├── List<TransitionDefinition> Transitions
    │   ├── string From
    │   ├── string Symbol
    │   └── string To
    ├── List<string> RequireAbsentTokens
    └── MetadataDefinition Metadata
        ├── string Severity        — Critical | High | Medium | Low
        ├── string Description
        └── List<string> Tags
```

---

### AppSettings

**File:** [`AppSettings.cs`](AppSettings.cs)

Serialized to/from `%AppData%\LogGuardV2\settings.json` by `SettingsService`.

```csharp
public class AppSettings
{
    // Source & Watch
    string LogDirectory      = @"C:\ProgramData\LogGuard\watch\";
    string WatchPattern      = "postgresql-*.log";
    string Timezone          = "UTC";
    string LogLineFormat     = "%m [%p] %q%u@%h %d ";
    bool   FollowRotation    = true;
    bool   ReplayOnStart     = false;

    // Parser
    bool ParseCoreFields        = true;
    bool ParseConnectionDetails = true;
    bool ParseQueryDetails      = true;
    bool ParseSystemMetrics     = false;
    bool ParseRawMessage        = true;
    bool RedactPasswords        = true;

    // Alerts
    string AlertWebhookUrl      = "https://hooks.internal/logguard/alerts";
    string AlertMinLevel        = "ERROR";
    bool   DesktopNotifications = true;
    bool   AudioBeepOnFatal     = false;
}
```

---

## NFA Automata System

### JSON Schema Reference

Every file in `NFA/` follows this schema:

```json
{
  "profileId":   "string — unique identifier (e.g. pgsql-sqli-v2)",
  "name":        "string — human-readable name",
  "version":     "string — semver",
  "enabled":     true,
  "threatType":  "SQLI | BRUTEFORCE | EXFIL | PRIVESC | DISCOVERY",
  "target": {
    "source":     "PostgreSQL",
    "inputField": "Query",
    "tokenizer":  "SqlTokenizer"
  },
  "alphabet": ["SELECT", "FROM", "WHERE", ...],
  "states": [
    { "id": "q0",    "isStart": true,  "isAccept": false },
    { "id": "q_end", "isStart": false, "isAccept": true  }
  ],
  "transitions": [
    { "from": "q0", "symbol": "SELECT", "to": "q_sel" }
  ],
  "requireAbsentTokens": ["WHERE", "LIMIT"],
  "metadata": {
    "severity":    "Critical | High | Medium | Low",
    "description": "What this profile detects",
    "tags":        ["sqli", "tautology"]
  }
}
```

**`requireAbsentTokens`** — optional negative constraint. The engine checks that none of these tokens appear anywhere in the token list before accepting a match. Used by `Exfiltration.json` to require the absence of `WHERE` and `LIMIT`.

---

### State and Transition Structure

States form a directed graph. The NFA engine builds an adjacency table:

```
_delta[fromStateId][tokenSymbol] = [toStateId, ...]
```

Multiple transitions from the same state on the same symbol are allowed (non-determinism). The engine tracks all simultaneously active states using a `HashSet<string>`.

**Naming conventions used in built-in profiles:**

| State Name | Meaning |
|---|---|
| `q0` | Initial state (always start) |
| `q_sel` | After SELECT |
| `q_from` | After FROM |
| `q_tbl` | Table position |
| `q_wh` / `q_where` | After WHERE |
| `q_col` | Column position |
| `q_eq` | After EQUALS |
| `q_val` | After value |
| `q_sqli` / `q_bf` / `q_ex` / `q_super` / `q_disc` | Accept states (threat confirmed) |

---

### How the Engine Loads and Executes Automata

**Load sequence:**

```
NfaLoader.LoadAll("NFA/")
  → foreach *.json in folder:
      → JsonSerializer.Deserialize<NFAModule.AutomatonProfile>(json)
      → if !profile.Enabled: skip
      → new NfaEngine(profile):
          → _startStates  = States.Where(s => s.IsStart).Select(s.Id)
          → _acceptStates = States.Where(s => s.IsAccept).Select(s.Id)
          → foreach transition: _delta[From][Symbol].Add(To)
```

**Execution sequence per log line:**

```
1. FileWatcherLive emits new lines
2. LogLiveWatcher.OnNewLines: multi-line accumulation → channel write
3. LogLiveWatcher.ConsumeEntries: async channel read
4. ProcessLine:
   a. PostgreSqlLogParser.TryParse(line) → PgLogEntry
   b. PID context update (ConnectionReceived / ConnectionAuthorized / Disconnection)
   c. Duration pairing (Duration lines pair with pending Statement entries)
   d. For Statement lines:
      → SqlTokenizer.Tokenize(pg.Message) → List<string> tokens
      → RunEngines(tokens):
          ≤4 engines: sequential foreach
          >4 engines: Parallel.ForEach with Break() on first match
      → if BRUTEFORCE match: IsBruteForce(key) sliding-window check
      → build LogEntry with PID context + match result
      → store in _pidPending[pid] awaiting Duration
5. Duration line arrives → dequeue from _pidPending → fire EntryDetected
6. EntryDetected → Dispatcher.InvokeAsync → UI thread → DataGrid insert
```

---

### Built-in Threat Profiles

#### SQL_Injection.json — `pgsql-sqli-v2`

**Severity:** High | **ThreatType:** SQLI

Detects 7 SQLi sub-patterns in a single automaton:

| Pattern | Trigger path |
|---|---|
| Direct tautology | `q0 → TAUTOLOGY → q_sqli` |
| SLEEP/pg_sleep | `q0 → SLEEP → q_sqli` |
| INFORMATION_SCHEMA access | `q0 → INFORMATION_SCHEMA → q_sqli` |
| OR bypass | `q0 → OR → q_or → NUMBER/STRING/TAUTOLOGY → q_sqli` |
| UNION injection | `q0 → UNION/UNION_ALL → q_union → SELECT → q_sqli` |
| Post-value injection | `q_val → OR/UNION/TAUTOLOGY/SLEEP/SEMICOLON → q_sqli` |
| Early termination (SEMICOLON) | `q_tbl → SEMICOLON → q_sqli` |

**State diagram:**
```
      TAUTOLOGY,SLEEP,INFORMATION_SCHEMA
    ┌───────────────────────────────────────────────────────► q_sqli ◄┐
    │    OR                                                             │
    │ q0 ──────► q_or ──── TAUTOLOGY/NUMBER/STRING ─────────────────────┤
    │    UNION                                                          │
    │    ├───────► q_union ─── SELECT ──────────────────────────────────┤
    │    SELECT                                                         │
    └──► q_prefix ─── FROM ──► q_tbl ─── WHERE ──► q_where ──► q_col ──► q_eq ──► q_val ──► (OR/UNION/...) ──►┘
                                │                    │                                                  SEMICOLON
                                └── SEMICOLON/INFO_SCHEMA ──────────────────────────────────────────────────────►┘
```

![NFA: SQL Injection](docs/assets/nfa-sqli.svg)

---

#### Brute_Force.json — `pgsql-bruteforce-v1`

**Severity:** Medium | **ThreatType:** BRUTEFORCE

Matches the credential-lookup pattern `SELECT ... FROM table WHERE col = 'value'`. A pattern match alone is not sufficient — `LogLiveWatcher.IsBruteForce()` requires **5+ matches per `user@host` key within 60 seconds** before raising an alert.

**State diagram:**
```
q0 ─SELECT─► q_sel ─FROM─► q_from ─IDENT─► q_tbl ─WHERE─► q_wh ─IDENT─► q_col ─EQUALS─► q_eq ─STRING─► q_bf [ACCEPT]
                  ↑
            IDENT/STAR self-loop
```

![NFA: Brute Force](docs/assets/nfa-bruteforce.svg)

---

#### Exfiltration.json — `pgsql-exfil-v1`

**Severity:** High | **ThreatType:** EXFIL

Detects bulk data dumps: `SELECT */cols FROM table` **without** `WHERE` or `LIMIT`. The `requireAbsentTokens: ["WHERE", "LIMIT"]` constraint prevents false positives on normal paginated queries.

**State diagram:**
```
q0 ─SELECT─► q_sel ─STAR─► q_kw_from ─FROM─► q_from ─IDENT─► q_ex [ACCEPT]
                  │                                    ▲
                  └────── FROM (no STAR) ──────────────┘
                  ↑
             IDENT self-loop
```

![NFA: Data Exfiltration](docs/assets/nfa-exfiltration.svg)

---

#### Privilege Escalation.json — `pgsql-privesc-v1`

**Severity:** Critical | **ThreatType:** PRIVESC

Detects `ALTER USER/ROLE <name> [WITH] SUPERUSER`. The `SUPERUSER` token also matches `REPLICATION`, `BYPASSRLS`, and `CREATEROLE` via the keyword dictionary — any privilege escalation to elevated roles is caught.

**State diagram:**
```
q0 ─ALTER─► q_alter ─USER/ROLE─► q_target ─IDENT─► q_name ─SUPERUSER─► q_super [ACCEPT]
                                                              │
                                                            WITH ─► q_with ─SUPERUSER─► q_super
```

![NFA: Privilege Escalation](docs/assets/nfa-privesc.svg)

---

#### Enumeration.json — `pgsql-discovery-v2`

**Severity:** Medium | **ThreatType:** DISCOVERY

Detects direct access to `information_schema`, `pg_shadow`, `pg_user`, `pg_roles`, `pg_authid`, `sysobjects`, and other system catalog tables. Both direct reference (`q0 → INFORMATION_SCHEMA → q_disc`) and post-FROM reference are caught.

![NFA: Schema Enumeration](docs/assets/nfa-enumeration.svg)

---

#### Time SQI.json — `pgsql-time-sqli-v2`

**Severity:** High | **ThreatType:** SQLI

Detects time-based blind SQLi via `SLEEP(N)`, `pg_sleep(N)`, or `BENCHMARK(N, ...)`. The `SLEEP` token is canonical for `SLEEP`, `PG_SLEEP`, and `DBMS_PIPE`. Matches `SELECT [ident] SLEEP(...)` and bare `SLEEP(...)` / `BENCHMARK(...)`.

![NFA: Time-based SQL Injection](docs/assets/nfa-time-sqli.svg)

---

## Processing Pipeline

### Full Pipeline Diagram

```
PostgreSQL Log File
      │
      │ (500ms poll, FileStream)
      ▼
FileWatcherLive
      │ NewLines event (IReadOnlyList<string>)
      ▼
LogLiveWatcher.OnNewLines()
  │ Multi-line accumulation (_pendingLine)
  │ LooksLikeHeader() check per line
  ▼
Channel<string>.Writer.TryWrite(line)
      │
      │ (async, single reader)
      ▼
LogLiveWatcher.ConsumeEntries()  [background Task]
      │
      ├── FLUSH control message → DoFlushStale()
      │
      └── Log line → ProcessLine()
              │
              ├─ TryParse() → PgLogEntry
              │
              ├─ ConnectionReceived  → _pidHost[pid] = host
              ├─ ConnectionAuthorized → _pidCtx[pid] = (user, db, host)
              ├─ Disconnection       → evict from all dicts
              │
              ├─ Duration line → pair with _pidPending[pid] → fire EntryDetected
              │
              └─ Statement line:
                    │
                    ├─ SqlTokenizer.Tokenize(sql) → List<string>
                    │      Phase 1: Normalize (comments, hex, percent, unicode, dollar)
                    │      Phase 2: MarkTautologies (5 bounded regex patterns)
                    │      Phase 3: ScanTokens (state machine)
                    │      Phase 4: FuseMultiword (UNION ALL, INTO OUTFILE, ...)
                    │
                    └─ RunEngines(tokens):
                           ≤4: sequential foreach
                           >4: Parallel.ForEach + Break
                           → NfaEngine.Run(tokens) → bool
                           → check RequireAbsentTokens
                           → if BRUTEFORCE: IsBruteForce(key) → sliding window
                           → build LogEntry
                           → _pidPending[pid] = (entry, TickCount64)

EntryDetected event (consumer thread)
      │
      ▼
Dispatcher.InvokeAsync (marshal to UI thread)
      │
      ▼
MainWindow.OnLiveEntry()
  - Interlocked counter updates
  - _fatalMinWindow sliding window (lock)
  - _entries.Insert(0, entry)   [newest first]
  - Cap at 5,000 entries
```

![Full Processing Pipeline](docs/assets/pipeline.svg)

---

### Multi-line Entry Buffering

PostgreSQL log entries can span multiple lines (continuation lines for `DETAIL`, `HINT`, `CONTEXT`). LogLiveWatcher handles this in `OnNewLines`:

```csharp
foreach (var raw in lines)
{
    if (!PostgreSqlLogParser.LooksLikeHeader(raw))
    {
        // Continuation line — append to current pending
        if (_pendingLine != null)
            _pendingLine = string.Concat(_pendingLine, "\n", raw.TrimStart());
        continue;
    }
    // New header — flush previous pending to channel
    if (_pendingLine != null)
        writer.TryWrite(_pendingLine);
    _pendingLine = raw;
}
// Flush last pending at end of each batch (critical for Duration lines)
if (_pendingLine != null) { writer.TryWrite(_pendingLine); _pendingLine = null; }
```

The final flush at batch end is critical: without it, `duration:` lines would remain buffered until the next batch, preventing Statement entries from ever being emitted.

---

### PID Context Correlation

PostgreSQL logs connection metadata in separate log lines from the actual queries. LogLiveWatcher correlates them by process ID:

```
1. connection received: host=192.168.1.10 port=54321
   → _pidHost[pid] = "192.168.1.10"

2. connection authorized: user=attacker database=mydb application_name=psql
   → _pidHost.Remove(pid, out stagedHost)
   → _pidCtx[pid] = ("attacker", "mydb", "192.168.1.10")

3. statement: SELECT * FROM users
   → _pidCtx.TryGetValue(pid, out ctx)
   → entry.UserHost = "attacker@192.168.1.10"
   → entry.Database = "mydb"

4. disconnection: ...
   → _pidCtx.Remove(pid)
   → _pidHost.Remove(pid)
   → _pidPending.Remove(pid)   ← prevents memory leak
```

---

### Duration Pairing

Every SQL statement has a corresponding `duration:` log line. LogLiveWatcher buffers the `LogEntry` in `_pidPending` until the duration line arrives:

```
Statement line (pid=1234):
  → build LogEntry with Duration = 0
  → _pidPending[1234] = (entry, TickCount64)

Duration line (pid=1234):
  → _pidPending.Remove(1234, out pending)
  → pending.Entry.Duration = 42.7   ← ms from "duration: 42.703 ms"
  → EntryDetected?.Invoke(pending.Entry)
```

**Stale flushing:** If a Duration line never arrives (connection dropped mid-query), the UI timer calls `FlushStale(2000)` every second. Entries older than 2 seconds are fired with `Duration = 0`.

---

### Brute-Force Sliding Window

Pattern match alone is insufficient for brute-force detection (normal apps also do credential lookups). LogLiveWatcher requires 5+ pattern matches per `user@host` key within 60 seconds:

```csharp
private bool IsBruteForce(string key)  // key = "user@host"
{
    var now = DateTimeOffset.UtcNow;
    if (!_bfWindow.TryGetValue(key, out var q))
        _bfWindow[key] = q = new Queue<DateTimeOffset>();

    q.Enqueue(now);
    while (q.Count > 0 && now - q.Peek() > TimeSpan.FromMinutes(1))
        q.Dequeue();

    return q.Count >= 5;
}
```

If `IsBruteForce` returns false, `matchedEngine` is set to null and the entry is logged without a threat flag.

---

## SQL Tokenizer Deep Dive

![SQL Tokenizer — 4-Phase Pipeline](docs/assets/tokenizer-pipeline.svg)

### Phase 1 — Normalization

Handles all structural transformations before tokenization. Runs as a single-pass state machine over the input string.

| Transformation | Input | Output |
|---|---|---|
| Block comment fusion | `SE/*evasion*/LECT` | `SELECT` |
| Line comment removal | `SELECT -- bypass` | `SELECT ` |
| Hex literal decode | `0x53454c454354` | ` SELECT ` |
| Percent-encode decode | `%53%45%4C%45%43%54` | `SELECT` |
| Unicode escape decode | `SELECT` | `SELECT` |
| Dollar-quote strip | `$$DROP TABLE$$` | `'DOLLARSTR'` |
| Single-quote passthrough | `'value'` | `'value'` |

Block comments are removed **without** inserting a space, allowing deliberately split keywords like `SE/*x*/LECT` to fuse back to `SELECT`.

---

### Phase 2 — Tautology Annotation

Five bounded regex patterns replace always-true boolean expressions with `__TAUTO__` marker (which Phase 3 maps to the `TAUTOLOGY` token):

| Pattern | Regex | Example |
|---|---|---|
| `TautoNumEq` | `\b(\d{1,10})\s*=\s*\1\b` | `1=1`, `42=42` |
| `TautoNumGt` | `\b[1-9]\d{0,9}\s*>\s*0\b` | `1>0`, `5>0` |
| `TautoNumNeq` | `\b(\d{1,10})\s*(?:<>\|!=)\s*(?!\1\b)\d{1,10}\b` | `1<>2`, `3!=7` |
| `TautoStrEq` | `'([^']{0,128})'\s*=\s*'\1'` | `'a'='a'` |
| `TautoIdentEq` | `(?<!\w)([A-Za-z_]\w{0,31})\s*=\s*\1(?!\w)` | `x=x`, `foo=foo` |

All capture groups are explicitly bounded — no catastrophic backtracking is possible.

---

### Phase 3 — State-Machine Scanner

No regex. Hand-written scanner processes the normalized string character by character:

```
char category      → token emitted
─────────────────────────────────
whitespace         → skip
letter / _ / @@    → scan identifier → lookup Keywords dict → KEYWORD or IDENT
digit              → scan number → NUMBER
' (single quote)   → scan string with '' escape → STRING
*                  → STAR
=                  → EQUALS
(                  → LPAREN
)                  → RPAREN
;                  → SEMICOLON
,                  → COMMA
! followed by =    → NEQ
< followed by >    → NEQ
< followed by =    → LTE
<                  → LT
> followed by =    → GTE
>                  → GT
|| (double pipe)   → CONCAT_OP
-- (line comment)  → COMMENT (defensive, Normalize should catch first)
/* (block comment) → COMMENT (defensive)
other              → skip
```

---

### Phase 4 — Multi-word Fusion

Consolidates adjacent tokens that represent single semantic units:

| Input sequence | Output token |
|---|---|
| `UNION ALL` | `UNION_ALL` |
| `INTO OUTFILE` | `INTO_OUTFILE` |
| `INTO DUMPFILE` | `INTO_OUTFILE` |
| `WAITFOR DELAY` | `WAITFOR_DELAY` |

---

### Token Reference Table

Complete keyword-to-token mapping (160+ entries, case-insensitive):

| SQL keyword(s) | Canonical token |
|---|---|
| `SELECT` | `SELECT` |
| `FROM` | `FROM` |
| `WHERE` | `WHERE` |
| `UNION` | `UNION` |
| `ALL` | `ALL` |
| `JOIN`, `INNER`, `OUTER`, `CROSS` | `JOIN` |
| `LIMIT` | `LIMIT` |
| `ORDER`, `GROUP`, `BY`, `HAVING` | as-is |
| `OR` | `OR` |
| `AND` | `AND` |
| `NOT`, `IN`, `LIKE`, `ILIKE` | `NOT`, `IN`, `LIKE` |
| `INSERT`, `REPLACE` | `INSERT` |
| `INTO` | `INTO` |
| `UPDATE`, `DELETE`, `MERGE` | as-is |
| `CREATE`, `DROP`, `ALTER`, `TRUNCATE` | as-is |
| `EXEC`, `EXECUTE`, `CALL`, `DO`, `SP_EXECUTESQL` | `EXEC` |
| `SLEEP`, `PG_SLEEP`, `DBMS_PIPE` | `SLEEP` |
| `BENCHMARK` | `BENCHMARK` |
| `WAITFOR` | `WAITFOR` |
| `CHAR`, `NCHAR`, `CHR` | `CHAR_FUNC` |
| `SUBSTRING`, `SUBSTR`, `MID` | `SUBSTR_FUNC` |
| `HEX`, `UNHEX`, `TO_HEX`, `ENCODE`, `DECODE` | `HEX_FUNC` |
| `CONCAT`, `CONCAT_WS`, `GROUP_CONCAT`, `STRING_AGG` | `CONCAT_FUNC` |
| `LOAD_FILE` | `LOAD_FILE` |
| `OUTFILE`, `DUMPFILE` | `OUTFILE` |
| `XP_CMDSHELL`, `XP_REGREAD`, `XP_REGWRITE`, `OPENROWSET`, `OPENDATASOURCE` | `XP_CMDSHELL` |
| `INFORMATION_SCHEMA` | `INFORMATION_SCHEMA` |
| `PG_SHADOW`, `PG_USER`, `PG_ROLES`, `PG_AUTHID` | `SYSTEM_TABLE` |
| `SYSOBJECTS`, `SYSCOLUMNS`, `ALL_TABLES`, `DBA_USERS`, `MSysObjects` | `SYSTEM_TABLE` |
| `GRANT` | `GRANT` |
| `REVOKE` | `REVOKE` |
| `SUPERUSER`, `REPLICATION`, `BYPASSRLS`, `CREATEROLE` | `SUPERUSER` |
| `VERSION`, `@@VERSION`, `@@SERVERNAME` | `VERSION` |
| `__TAUTO__` (internal marker) | `TAUTOLOGY` |
| any other identifier | `IDENT` |
| numeric literal | `NUMBER` |
| quoted string | `STRING` |

---

### Evasion Resistance

The tokenizer is designed to neutralize common SQLi obfuscation techniques:

| Evasion technique | Neutralized by |
|---|---|
| Comment splitting `SE/**/LECT` | Phase 1: block comment fusion (no space insertion) |
| Hex encoding `0x53454c454354` | Phase 1: hex literal decode |
| URL encoding `%53%45%4C%45%43%54` | Phase 1: percent-decode |
| Unicode escapes `SELECT` | Phase 1: unicode decode |
| PostgreSQL dollar-quotes `$$payload$$` | Phase 1: dollar-quote stripping |
| Case variation `SeLeCt` | Phase 3: case-insensitive keyword lookup |
| Tautology variants `1=1`, `'a'='a'`, `x=x` | Phase 2: canonical TAUTOLOGY token |
| Synonym functions `ILIKE` → `LIKE`, `CALL` → `EXEC` | Phase 3: keyword dict aliases |
| Multi-engine evasion `UNION ALL` vs `UNION` | Phase 4: UNION_ALL fusion |
| ReDoS via crafted input | Phase 3: no regex — state machine only |

---

## Threading and Concurrency

```
Thread / Task          Runs on              Accesses
─────────────────────────────────────────────────────────────────────
UI Thread              WPF Dispatcher       _entries, _view, KPI labels,
                                            charts, filter predicates
                                            (Interlocked reads for counters)

Timer Thread           System.Threading.Timer  FileWatcherLive._readLock
(FileWatcherLive)      (pool thread)           _pendingLine (under lock)

Consumer Task          Task.Run (pool)      _pidCtx, _pidHost, _pidPending,
(LogLiveWatcher)                            _bfWindow, _engines (via snapshot)
                                            Channel reader (single reader)

Channel Writer         Timer thread         Channel.Writer (TryWrite)
                       UI thread (FlushStale)
```

**Synchronization primitives:**

| Primitive | Protects |
|---|---|
| `Interlocked` (long ops) | `_totalEvents`, `_fatalErrorCount`, `_injectedCount`, `_durationSumUs`, `_durationCount`, `_eventsThisSecond`, `_injectedThisSecond`, `_fatalThisSecond` |
| `lock (_fatalWindowLock)` | `_fatalMinWindow` queue (UI thread + timer thread) |
| `Interlocked.Exchange` | `_engines` list swap during `ReloadEngines()` |
| `Channel<string>` | Decouples producer (file watcher) from consumer (analysis task) |
| `Dispatcher.InvokeAsync` | Marshals `EntryDetected` from consumer task to UI thread |

**Why plain `Dictionary` is safe in consumer task:** `SingleReader = true` on the channel guarantees `ConsumeEntries` is the only task reading from the channel. All dictionary access (`_pidCtx`, `_pidHost`, `_pidPending`, `_bfWindow`) happens exclusively within `ConsumeEntries` → `ProcessLine`. No locking required.

---

## Real-time Detection System

Detection results are surfaced in two UI areas:

**Threat Monitor DataGrid:** Each `LogEntry` shows `IsInjected = true` with a colored `● YES` badge and the `ThreatType` string (`SQLI`, `BRUTEFORCE`, `EXFIL`, `PRIVESC`, `DISCOVERY`). Severity level determines row stripe color.

**KPI Bar (refreshed every 1s):**

| KPI | Calculation |
|---|---|
| Events/sec | `_eventsThisSecond` (Interlocked reset each tick) |
| Fatal/Error | Count in `_fatalMinWindow` within last 60s |
| Injected/s | `_injectedThisSecond` (Interlocked reset each tick) |
| Avg Duration | `_durationSumUs / _durationCount` (μs precision) |
| Uptime | `DateTime.UtcNow - _appStart` |

**Sparklines** (48-point rolling history, 1s per point): QPS, Injected/s, Fatal/s, Avg Duration — drawn as line + area charts on `Canvas` elements.

**Dashboard charts:**
- **Level distribution** — bar chart by severity level from current `_entries`
- **Top databases** — horizontal bar chart (top 5 by occurrence)
- **Duration histogram** — log-scale histogram with p95 marker line

---

## Alert System

Alert configuration lives in `AppSettings`:

```
AlertWebhookUrl      — POST target for webhook alerts
AlertMinLevel        — Minimum severity to alert (ERROR, CRITICAL, etc.)
DesktopNotifications — Windows toast notifications
AudioBeepOnFatal     — System beep on FATAL level
```

Webhook delivery infrastructure is stubbed in `AppSettings` and wired through the settings UI. Implementation can be added in `LogLiveWatcher.EntryDetected` handler or `MainWindow.OnLiveEntry`.

---

## UI Architecture

### Threat Monitor Tab

Primary tab. Visible by default on startup.

**Layout (top to bottom):**
1. Header bar — Start/Stop watcher button, active module count badge
2. KPI bar — 5 metric cells with trend indicators
3. Filter bar — search box + 6 severity toggle chips (CRITICAL, HIGH, MEDIUM, LOW, WARNING, LOG)
4. DataGrid — virtualized, newest-first, capped at 5,000 entries

**DataGrid columns:**

| Column | Binding | Notes |
|---|---|---|
| Timestamp | `Timestamp` | `yyyy-MM-dd HH:mm:ss.fff UTC` |
| PID | `Pid` | PostgreSQL process ID |
| Level | `Level` | Severity badge with per-level color |
| User@Host | `UserHost` | Correlated via PID context |
| Database | `Database` | From `ConnectionAuthorized` |
| Query | `Query` | Truncated to cell width |
| Duration | `Duration` | Formatted via `DurFmtConverter` |
| Injected | `IsInjected` | `● YES` / `—` with background color |
| Threat | `ThreatType` | `SQLI` / `BRUTEFORCE` / etc. |

**Filtering:** `ICollectionView` filter predicate checks `Level` against `_activeFilters` and `Query + UserHost + Database + ThreatType` against `_searchText` (case-insensitive contains).

---

### Dashboard Tab

Visualization of aggregated metrics from current session data.

**Panels:**
- 4 KPI sparkline panels (Canvas-based line + area charts, 48 time points)
- Level distribution bar chart
- Top 5 databases horizontal bar chart
- Query duration log-scale histogram with p95 marker

All charts are redrawn on KPI timer tick (every 1s).

---

### Module Manager Tab

Grid of NFA profile cards. Each card shows:
- Threat type badge
- Profile name + enabled toggle
- State diagram (circles for each state, filled for accept states)
- Stats table (state count, transition count, version, severity)
- Description text
- Filename + Reload button

**Operations:**
- Enable/disable toggle — writes `"enabled": true/false` back to JSON, calls `ReloadEngines()`
- Reload button — re-deserializes single file, rebuilds card
- Import button — `OpenFileDialog` for `.json` files, copies to `NFA/` folder, reloads

---

### Settings Tab

Scrollable form with 3 sections:

**Source & Watch** — log directory path, glob pattern, timezone, log format, rotation/replay toggles

**Parser** — field-level toggle grid (core fields, connection details, query details, system metrics, raw message, password redaction)

**Alerts** — webhook URL, minimum alert level dropdown, desktop notification toggle, audio beep toggle

On Save: deserializes form → `SettingsService.Save()` → optionally restarts `LogLiveWatcher` with new settings.

---

## Configuration

**Settings file location:** `%AppData%\LogGuardV2\settings.json`

**Minimal configuration example:**
```json
{
  "LogDirectory": "C:\\PostgreSQL\\data\\pg_log\\",
  "WatchPattern": "postgresql-*.log",
  "Timezone": "UTC",
  "FollowRotation": true,
  "ReplayOnStart": false,
  "ParseCoreFields": true,
  "ParseConnectionDetails": true,
  "ParseQueryDetails": true,
  "RedactPasswords": true,
  "AlertMinLevel": "ERROR",
  "DesktopNotifications": true
}
```

**PostgreSQL `postgresql.conf` requirements:**

```ini
log_destination = 'stderr'
logging_collector = on
log_directory = 'pg_log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d

# Required for statement logging
log_statement = 'all'          # or 'ddl' / 'mod'
log_duration = on

# Required for connection context
log_connections = on
log_disconnections = on

# Line prefix must match expected format
log_line_prefix = '%m [%p] %q%u@%h %d '
```

**NFA folder:** `NFA/` relative to the executable. All `.json` files are auto-loaded on startup and on `ReloadEngines()`.

---

## Examples

### Detection Examples

**SQL Injection — Tautology:**
```sql
SELECT * FROM users WHERE id = '1' OR '1'='1'
```
Tokens: `SELECT STAR FROM IDENT WHERE IDENT EQUALS STRING OR TAUTOLOGY`
Match: `q0 → OR → q_or → TAUTOLOGY → q_sqli [ACCEPT]`
Result: `IsInjected=true, ThreatType=SQLI, Level=HIGH`

---

**SQL Injection — UNION:**
```sql
SELECT name FROM products WHERE id=1 UNION ALL SELECT username,password FROM users
```
Tokens: `SELECT IDENT FROM IDENT WHERE IDENT EQUALS NUMBER UNION_ALL SELECT IDENT COMMA IDENT FROM IDENT`
Match: `q0 → UNION_ALL → q_union → SELECT → q_sqli [ACCEPT]`
Result: `IsInjected=true, ThreatType=SQLI, Level=HIGH`

---

**SQL Injection — Time-based blind:**
```sql
SELECT pg_sleep(5)
```
Tokens: `SELECT SLEEP LPAREN NUMBER RPAREN`
Match (Time SQI): `q0 → SELECT → q_sel → SLEEP → q_func → LPAREN → q_arg → NUMBER → q_arg → RPAREN → q_alert [ACCEPT]`
Result: `IsInjected=true, ThreatType=SQLI, Level=HIGH`

---

**Privilege Escalation:**
```sql
ALTER USER postgres WITH SUPERUSER
```
Tokens: `ALTER USER IDENT WITH SUPERUSER`
Match: `q0 → ALTER → q_alter → USER → q_target → IDENT → q_name → WITH → q_with → SUPERUSER → q_super [ACCEPT]`
Result: `IsInjected=true, ThreatType=PRIVESC, Level=CRITICAL`

---

**Data Exfiltration:**
```sql
SELECT * FROM customers
```
Tokens: `SELECT STAR FROM IDENT`
Absent tokens check: `WHERE` ✗ not present, `LIMIT` ✗ not present → constraint satisfied
Match: `q0 → SELECT → q_sel → STAR → q_kw_from → FROM → q_from → IDENT → q_ex [ACCEPT]`
Result: `IsInjected=true, ThreatType=EXFIL, Level=HIGH`

```sql
SELECT * FROM customers WHERE active=1 LIMIT 100
```
Tokens: `SELECT STAR FROM IDENT WHERE IDENT EQUALS NUMBER LIMIT NUMBER`
Absent tokens check: `WHERE` ✓ present → constraint **blocked**
Result: `IsInjected=false` (normal paginated query)

---

**Schema Enumeration:**
```sql
SELECT table_name FROM information_schema.tables
```
Tokens: `SELECT IDENT FROM INFORMATION_SCHEMA IDENT`
Match: `q0 → SELECT → q_sel → FROM → q_from → INFORMATION_SCHEMA → q_disc [ACCEPT]`
Result: `IsInjected=true, ThreatType=DISCOVERY, Level=MEDIUM`

---

### Tokenization Examples

**Basic normalization:**
```
Input:  SE/*comment*/LECT 0x55534552 FROM pg_shadow
Phase1: SELECT  USER  FROM pg_shadow
Phase2: SELECT  USER  FROM pg_shadow   (no tautology)
Phase3: SELECT IDENT FROM SYSTEM_TABLE
Phase4: SELECT IDENT FROM SYSTEM_TABLE
Output: [SELECT, IDENT, FROM, SYSTEM_TABLE]
```

**Evasion via percent-encoding:**
```
Input:  %53%45%4C%45%43%54 * %46%52%4F%4D users
Phase1: SELECT * FROM users
Phase3: SELECT STAR FROM IDENT
Output: [SELECT, STAR, FROM, IDENT]
```

**Tautology variants:**
```
Input:  WHERE id=5 OR 1=1
Phase2: WHERE id=5 OR  __TAUTO__
Phase3: WHERE IDENT EQUALS NUMBER OR TAUTOLOGY
Output: [WHERE, IDENT, EQUALS, NUMBER, OR, TAUTOLOGY]
```

**Multi-word fusion:**
```
Input:  ... UNION ALL SELECT ...
Phase3: [..., UNION, ALL, SELECT, ...]
Phase4: [..., UNION_ALL, SELECT, ...]
Output: [..., UNION_ALL, SELECT, ...]
```

---

### Automaton Trace Examples

**Brute_Force NFA trace — match:**
```
Tokens: [SELECT, STAR, FROM, IDENT, WHERE, IDENT, EQUALS, STRING]
Step 0: active={q0}
         SELECT → q0→q_sel; +start → {q0, q_sel}
Step 1: active={q0, q_sel}
         STAR   → q_sel→q_sel; +start → {q0, q_sel}
Step 2: active={q0, q_sel}
         FROM   → q_sel→q_from; +start → {q0, q_from}
Step 3: active={q0, q_from}
         IDENT  → q_from→q_tbl; +start → {q0, q_tbl}
Step 4: active={q0, q_tbl}
         WHERE  → q_tbl→q_wh; +start → {q0, q_wh}
Step 5: active={q0, q_wh}
         IDENT  → q_wh→q_col; +start → {q0, q_col}
Step 6: active={q0, q_col}
         EQUALS → q_col→q_eq; +start → {q0, q_eq}
Step 7: active={q0, q_eq}
         STRING → q_eq→q_bf; +start → {q0, q_bf}
         q_bf ∈ acceptStates → MATCH
```

Then `IsBruteForce("user@host")` checks rate: only fires if 5+ in 60s.

---

### Log Line Parsing Examples

**Statement line:**
```
2024-01-15 14:23:01.437 UTC [1984] LOG:  statement: SELECT * FROM users WHERE id=1 OR 1=1
```
Parsed: `PgLogEntry { Type=Statement, ProcessId="1984", Severity="LOG", Message="SELECT * FROM users WHERE id=1 OR 1=1", Timestamp=2024-01-15T14:23:01.437+00:00 }`

**Duration line:**
```
2024-01-15 14:23:01.445 UTC [1984] LOG:  duration: 7.823 ms
```
Parsed: `PgLogEntry { Type=Duration, ProcessId="1984", DurationMs=7.823 }`
Action: dequeue `_pidPending[1984]`, set `Duration=7.823`, fire `EntryDetected`

**Connection received:**
```
2024-01-15 14:23:01.102 UTC [1984] LOG:  connection received: host=192.168.1.10 port=54321
```
Parsed: `PgLogEntry { Type=ConnectionReceived, Host="192.168.1.10", Port=54321 }`
Action: `_pidHost[1984] = "192.168.1.10"`

**Connection authorized:**
```
2024-01-15 14:23:01.115 UTC [1984] LOG:  connection authorized: user=attacker database=mydb application_name=psql
```
Parsed: `PgLogEntry { Type=ConnectionAuthorized, User="attacker", Database="mydb" }`
Action: `_pidCtx[1984] = ("attacker", "mydb", "192.168.1.10")`

---

## Adding New Detection Rules

### Writing a New NFA Profile

**Step 1 — Define threat pattern.** Write out the token sequence you want to catch. Example: detecting `EXEC xp_cmdshell(...)`:

```
Target tokens: EXEC XP_CMDSHELL LPAREN ... RPAREN
```

**Step 2 — Design states and transitions:**

```
q0 ─EXEC──────────────────────────────────► q_exec
q_exec ─XP_CMDSHELL───────────────────────► q_xp
q_xp ─LPAREN──────────────────────────────► q_arg
q_arg ─STRING/IDENT/NUMBER/COMMA/LPAREN───► q_arg  (self-loops for argument content)
q_arg ─RPAREN──────────────────────────────► q_alert [ACCEPT]
```

**Step 3 — Write the JSON file:**

```json
{
  "profileId": "pgsql-cmdshell-v1",
  "name": "OS Command Execution - xp_cmdshell",
  "version": "1.0.0",
  "enabled": true,
  "threatType": "PRIVESC",
  "target": {
    "source": "PostgreSQL",
    "inputField": "Query",
    "tokenizer": "SqlTokenizer"
  },
  "alphabet": ["EXEC", "XP_CMDSHELL", "LPAREN", "RPAREN", "STRING", "IDENT", "NUMBER", "COMMA"],
  "states": [
    { "id": "q0",      "isStart": true,  "isAccept": false },
    { "id": "q_exec",  "isStart": false, "isAccept": false },
    { "id": "q_xp",    "isStart": false, "isAccept": false },
    { "id": "q_arg",   "isStart": false, "isAccept": false },
    { "id": "q_alert", "isStart": false, "isAccept": true  }
  ],
  "transitions": [
    { "from": "q0",     "symbol": "EXEC",       "to": "q_exec"  },
    { "from": "q_exec", "symbol": "XP_CMDSHELL","to": "q_xp"    },
    { "from": "q_xp",   "symbol": "LPAREN",     "to": "q_arg"   },
    { "from": "q_arg",  "symbol": "STRING",      "to": "q_arg"   },
    { "from": "q_arg",  "symbol": "IDENT",       "to": "q_arg"   },
    { "from": "q_arg",  "symbol": "NUMBER",      "to": "q_arg"   },
    { "from": "q_arg",  "symbol": "COMMA",       "to": "q_arg"   },
    { "from": "q_arg",  "symbol": "LPAREN",      "to": "q_arg"   },
    { "from": "q_arg",  "symbol": "RPAREN",      "to": "q_alert" }
  ],
  "metadata": {
    "severity": "Critical",
    "description": "Detects EXEC xp_cmdshell(...) — OS command execution via SQL Server stored procedure",
    "tags": ["privesc", "rce", "xp_cmdshell"]
  }
}
```

**Step 4 — Deploy:** Place the file in the `NFA/` folder. Use Module Manager → Reload All, or restart the watcher. The engine auto-loads all enabled profiles.

---

**Design guidelines:**

| Rule | Reason |
|---|---|
| Start from `q0`, avoid making `q0` an accept state | Prevents matching empty input |
| Add self-loops for wildcard spans (`IDENT` → same state) | Handles intervening tokens without disrupting path |
| Use `requireAbsentTokens` for negative constraints | Prevents false positives without adding NOT-states |
| Keep alphabet minimal | Only list symbols that appear in transitions; others are implicitly ignored |
| Use `TAUTOLOGY` not `EQUALS + NUMBER + EQUALS` | Canonical token covers all tautology variants |
| Use `SLEEP` not `PG_SLEEP` | Keyword dict maps both to `SLEEP` |
| Test with tokenizer output first | `SqlTokenizer.Tokenize(sql)` shows exact tokens the NFA will see |

---

### Extending the Tokenizer

**Add new keyword:** Insert into the `Keywords` dictionary in [`SqlTokenizer.cs`](src/Engine/SqlTokenizer.cs):

```csharp
// Map all variants to a canonical token
["NEW_FUNCTION"]   = "NEW_TOKEN",
["NEW_FUNC_ALIAS"] = "NEW_TOKEN",
```

**Add new tautology pattern:** Add a compiled static `Regex` and apply it in `MarkTautologies()`:

```csharp
private static readonly Regex TautoMyPattern = new(
    @"\bYOUR_BOUNDED_PATTERN\b",
    RegexOptions.Compiled | RegexOptions.CultureInvariant);

private static string MarkTautologies(string sql)
{
    sql = TautoStrEq.Replace(sql, " __TAUTO__ ");
    // ...existing patterns...
    sql = TautoMyPattern.Replace(sql, " __TAUTO__ ");  // add here
    return sql;
}
```

**CRITICAL:** All tautology regex patterns must be provably bounded. Use explicit character class lengths (`{0,N}`) and avoid nested quantifiers. ReDoS in Phase 2 would block the consumer task.

**Add new multi-word fusion:** Add a `case` in `FuseMultiword()`:

```csharp
case "MY_KEYWORD" when next == "MY_NEXT": result.Add("MY_FUSED"); i++; break;
```

**Add new structural token:** Add a `case` in the `switch (c)` block in `ScanTokens()`:

```csharp
case '~': tokens.Add("TILDE"); i++; break;
```

---

### Adding New Log Line Types

**Step 1 — Add enum value** in `PostgreSqlLogParser.cs`:
```csharp
public enum PgLogLineType
{
    // ...existing...
    MyNewType
}
```

**Step 2 — Add compiled regex:**
```csharp
private static readonly Regex MyNewTypeRegex = new(
    @"^my prefix:\s+field=(?<field>\S+)$",
    RegexOptions.Compiled | RegexOptions.CultureInvariant);
```

**Step 3 — Handle in `ParseTypedMessage()`:**
```csharp
m = MyNewTypeRegex.Match(message);
if (m.Success)
{
    entry.Type = PgLogLineType.MyNewType;
    // populate entry fields
    return;
}
```

**Step 4 — Handle in `LogLiveWatcher.ProcessLine()`:**
```csharp
if (pg.Type == PgLogLineType.MyNewType)
{
    // update PID context, fire events, etc.
    return;
}
```

---

## Performance

### Throughput Characteristics

| Operation | Typical latency | Notes |
|---|---|---|
| File poll cycle | ~0ms | Idle when no new data |
| Log line parse | < 0.1ms | Pre-compiled regex |
| SQL tokenization | < 0.5ms | State machine, no regex in hot path |
| NFA match (per engine) | < 0.3ms | O(tokens × states) |
| End-to-end (parse → alert) | < 5ms | Dominated by channel scheduling |
| UI DataGrid insert | < 1ms | ObservableCollection at position 0 |

### Memory Usage

| Component | Memory |
|---|---|
| DataGrid buffer | ~5,000 `LogEntry` objects (~2MB typical) |
| NFA state tables | < 1KB per engine (sparse dict) |
| Sparkline history | 4 × 48 doubles = 1.5KB |
| Per-PID context dicts | Bounded by active connection count |
| Brute-force windows | Max 1 entry per request (60s TTL) |

### Tuning

**Reduce CPU usage on idle servers:**
- Increase `FileWatcherLive` poll interval (currently 500ms hardcoded; extract to `AppSettings` if needed)
- Set `ReplayOnStart = false` (default) — avoids re-tokenizing historical data

**Increase throughput for high-volume logs:**
- Disable unused NFA profiles via Module Manager (reduces `RunEngines` iterations)
- The sequential path (≤4 engines) has lower overhead than parallel; prune profiles aggressively
- For > 4 engines: `Parallel.ForEach` + `Break()` stops on first match — order profiles by frequency of expected hits

**DataGrid rendering under high load:**
- The 5,000-entry cap prevents unbounded ObservableCollection growth
- `ICollectionView` filter runs on the UI thread — complex filters with many active entries can lag; prefer simple Contains checks

**Channel backpressure:**
- `Channel.CreateUnbounded` — no backpressure. If the consumer falls behind, memory grows unbounded.
- For sustained high-rate logs, consider switching to `Channel.CreateBounded` with a drop policy

---

## Security Considerations

### Input Validation

The tokenizer is the security boundary — it must handle adversarial SQL without crashing or hanging:

- **ReDoS:** Phase 3 uses a state machine (no regex). Phase 2 tautology regexes have provably bounded capture groups. Adding new Phase 2 patterns requires proof of boundedness.
- **Memory:** Hex literal decode is bounded to 512 hex chars (256 bytes output). Dollar-quote scanning uses `string.IndexOf` (linear). Single-quote scanning is linear.
- **Null input:** `SqlTokenizer.Tokenize` returns empty list on null/empty. `LogLiveWatcher.ProcessLine` guards against empty lines.

### Log File Access

`FileWatcherLive` opens log files with default share mode — does not lock files, allowing PostgreSQL to continue writing. If the log file is replaced during rotation, the watcher detects the new file within 500ms.

### Settings Security

- Settings stored in `%AppData%` (user-writable) — not suitable for multi-user environments where settings must be protected
- `AlertWebhookUrl` is transmitted as plain HTTP if not HTTPS — configure TLS endpoints only
- No secrets are stored in `AppSettings` — webhook authentication should be handled via URL parameters or headers added in the webhook implementation

### NFA Profile Integrity

NFA profiles are loaded from the `NFA/` folder relative to the executable. In production environments:

- Restrict write access to the `NFA/` folder to administrators
- Profile files are deserialized with default `JsonSerializer` settings — they can contain only the fields defined in `NFAModule.AutomatonProfile`
- Malformed profiles are silently skipped (see `NfaLoader.LoadAll`) — a tampered profile that parses but contains incorrect transitions will silently fail to detect threats; monitor engine count changes

### Thread Safety

All fields accessed from multiple threads are properly synchronized (see [Threading and Concurrency](#threading-and-concurrency)). The `_engines` list reference is swapped atomically — engines currently running `Run()` complete safely because `NfaEngine.Run()` is stateless.

---

## Troubleshooting

### No entries appearing in Threat Monitor

1. Verify the watcher is started (green indicator in status bar)
2. Check `LogDirectory` points to the correct folder — use Browse button and Test Pattern button in Settings
3. Verify PostgreSQL has `log_statement = 'all'` and `logging_collector = on`
4. Verify `log_line_prefix = '%m [%p] %q%u@%h %d '` — the parser requires this exact format
5. Check `EngineCount` badge (header bar) — if 0, no profiles loaded; check `NFA/` folder exists in executable directory
6. Try `ReplayOnStart = true` in Settings to replay existing log content

### Entries appear but no threats detected

1. Open Module Manager and verify profiles are enabled (toggle must be ON)
2. Use the tokenizer to manually inspect output: add temporary debug `Console.WriteLine(string.Join(",", SqlTokenizer.Tokenize(yourSql)))` in a test
3. Verify the SQL reaches the parser as `PgLogLineType.Statement` — `duration:` lines are not tokenized
4. Check `requireAbsentTokens` — exfiltration detection requires absence of WHERE/LIMIT

### Brute-force alerts not triggering

Brute-force requires 5 pattern matches per `user@host` key within 60 seconds. Confirm:
- The credential-lookup pattern `SELECT ... FROM table WHERE col = 'value'` actually matches (check tokenization)
- Attacks come from the same `user@host` pair — different hosts or users are tracked separately
- 5 attempts arrive within a single 60-second window

### High memory usage

- Check DataGrid entry count — if close to 5,000, reduce retention via filter chips to hide lower-severity entries
- If `_pidPending` grows unbounded, Duration lines may not be arriving — check `log_duration = on` in PostgreSQL config
- `FlushStale` (called every 1s) evicts entries older than 2s — verify the KPI timer is running (status bar clock should update)

### Log rotation not detected

- `FollowRotation` must be enabled in Settings
- Detection occurs on the next 500ms poll cycle after the new file appears
- `WatchPattern` must match the rotated filename (e.g. `postgresql-*.log` matches `postgresql-2024-01-15_000000.log`)

### NFA profile reload not taking effect

- `ReloadEngines()` swaps the engine list atomically — existing in-progress `Run()` calls complete with old engines
- Verify the JSON is valid and `"enabled": true` — use Module Manager Reload button to see parse errors
- Engine count badge updates immediately after reload

### Settings not persisting

- Settings are saved to `%AppData%\LogGuardV2\settings.json` — verify the process has write access
- If `%AppData%` is redirected (roaming profiles, UWP sandbox), check the actual path
- Settings are loaded at startup — changes take effect after Save + watcher restart

---

## Dependencies

| Dependency | Version | Source |
|---|---|---|
| .NET Runtime | 10.0 (Windows) | Microsoft |
| WPF | Included in net10.0-windows | Microsoft |
| `System.Text.Json` | Included in .NET 10 | Microsoft |
| `System.Threading.Channels` | Included in .NET 10 | Microsoft |

No external NuGet packages. Zero third-party dependencies.

**Build requirements:**
- .NET 10 SDK (Windows)
- Visual Studio 2022+ or `dotnet build` CLI

```bash
dotnet build LogGuardV2.csproj -c Release
dotnet run --project LogGuardV2.csproj
```

---

## Future Extensions

### Additional Threat Profiles

| Profile idea | ThreatType | Key tokens |
|---|---|---|
| `COPY TO / FROM` exfiltration | `EXFIL` | `COPY, FROM, TO, OUTFILE` |
| `pg_read_file()` / `pg_ls_dir()` | `DISCOVERY` | `IDENT (pg_read_file)` |
| `CREATE EXTENSION` abuse | `PRIVESC` | `CREATE, IDENT (extension name)` |
| Stacked queries | `SQLI` | `SEMICOLON, SELECT/INSERT/DROP` |
| Error-based SQLi via `CAST` | `SQLI` | `CAST, CHAR_FUNC, CONCAT_FUNC` |
| `LOAD_FILE()` | `EXFIL` | `LOAD_FILE, LPAREN, STRING` |

### Engine Improvements

- **Named capture groups in NFA:** Allow profiles to capture which state path was taken for richer alert context
- **Regex-backed transitions:** Support `~` symbol meaning "any token" for wildcard spans (currently handled via self-loops)
- **Composite profiles:** AND/OR logic across multiple profiles before raising a single alert
- **Severity override rules:** Dynamic severity based on target database or user

### Infrastructure

- **Webhook delivery:** Implement `HttpClient` POST in `MainWindow.OnLiveEntry` for real alert delivery
- **SQLite audit log:** Persist `LogEntry` objects to local SQLite for post-incident analysis
- **Export:** CSV/JSON export of current DataGrid view
- **Remote monitoring:** Replace `FileWatcherLive` with a gRPC or SignalR stream for remote log ingestion
- **Multi-file monitoring:** Watch multiple PostgreSQL instances simultaneously
- **Linux/macOS support:** Replace WPF with Avalonia UI for cross-platform deployment
