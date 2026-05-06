using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using LogGuardV2.src.Model;

namespace LogGuardV2.src.Engine
{
    /// <summary>
    /// Orchestrates live log monitoring:
    ///   FileWatcherLive → PostgreSqlLogParser → SqlTokenizer → NfaEngine[] → LogEntry
    ///
    /// File I/O and NFA processing are decoupled via a Channel: OnNewLines (called
    /// under the file-watcher lock) only accumulates multi-line entries and enqueues
    /// them; a dedicated consumer task performs all CPU-heavy work independently.
    ///
    /// Raises <see cref="EntryDetected"/> on the consumer task thread.
    /// Callers must dispatch to the UI thread before touching UI objects.
    /// </summary>
    internal sealed class LogLiveWatcher : IDisposable
    {
        private readonly FileWatcherLive _fileWatcher;
        private readonly string          _nfaFolder;
        private List<NfaEngine>          _engines;

<<<<<<< Updated upstream
        // Decouples file-watcher I/O from NFA processing.
        // SingleWriter = OnNewLines (always under _readLock), SingleReader = consumer task.
        private readonly Channel<string> _entryChannel = Channel.CreateUnbounded<string>(
            new UnboundedChannelOptions
            {
                SingleReader                  = true,
                SingleWriter                  = true,
                AllowSynchronousContinuations = false
            });
        private readonly Task _consumer;

        // C1: PID → (User, Database, Host) — only accessed from consumer task (single reader)
        private readonly Dictionary<int, (string User, string Database, string Host)> _pidCtx = new();

        // A3: brute-force sliding window — only accessed from consumer task
        private readonly Dictionary<string, Queue<DateTimeOffset>> _bfWindow = new();
        private const int BfThreshold = 5;
        private static readonly TimeSpan BfWindowDuration = TimeSpan.FromMinutes(1);

        // M5: pending multi-line accumulation — only accessed from OnNewLines (under file-watcher lock)
        private string? _pendingLine;
=======
        // C1: PID → (User, Database, Host) from ConnectionAuthorized entries
        private readonly ConcurrentDictionary<int, (string User, string Database, string Host)> _pidCtx = new();

        // Host staging: PID → host from ConnectionReceived, consumed on ConnectionAuthorized
        private readonly ConcurrentDictionary<int, string> _pidHost = new();

        // D1: PID → buffered statement entry awaiting its paired Duration line
        private readonly ConcurrentDictionary<int, (LogEntry Entry, long CreatedTick)> _pidPending = new();

        // A3: brute-force sliding window — key = "user@host"
        private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _bfWindow = new();
        private const int BfThreshold = 5;
        private static readonly TimeSpan BfWindowDuration = TimeSpan.FromMinutes(1);

        // M5: pending multi-line accumulation
        private volatile string? _pendingLine;
>>>>>>> Stashed changes

        public int EngineCount => _engines.Count;

        public event Action<LogEntry>? EntryDetected;

        public LogLiveWatcher(AppSettings settings, string nfaFolder)
        {
            _nfaFolder   = nfaFolder;
            _engines     = NfaLoader.LoadAll(nfaFolder);
            _fileWatcher = new FileWatcherLive(
                settings.LogDirectory, settings.WatchPattern, settings.FollowRotation);
            _fileWatcher.NewLines += OnNewLines;
            _consumer = Task.Run(ConsumeEntries);
        }

        public void Start(bool replayFromStart = false) => _fileWatcher.Start(replayFromStart);

        // A5: hot reload — swaps engine list atomically
        public void ReloadEngines()
            => Interlocked.Exchange(ref _engines, NfaLoader.LoadAll(_nfaFolder));

<<<<<<< Updated upstream
        // ── Pipeline: producer side (runs under FileWatcherLive._readLock) ─────────
=======
        // D1: flush pending entries older than maxAgeMs that never received a Duration line
        public void FlushStale(long maxAgeMs = 2000)
        {
            var now = Environment.TickCount64;
            foreach (var kvp in _pidPending)
            {
                if (now - kvp.Value.CreatedTick >= maxAgeMs)
                {
                    if (_pidPending.TryRemove(kvp.Key, out var pending))
                        EntryDetected?.Invoke(pending.Entry);
                }
            }
        }

        // ── Pipeline ──────────────────────────────────────────────────────────────
>>>>>>> Stashed changes

        private void OnNewLines(IReadOnlyList<string> lines)
        {
            var writer = _entryChannel.Writer;
            foreach (var raw in lines)
            {
                // M5: accumulate continuation lines (DETAIL/HINT/CONTEXT)
                if (!PostgreSqlLogParser.LooksLikeHeader(raw))
                {
                    if (_pendingLine != null)
                        _pendingLine = string.Concat(_pendingLine, "\n", raw.TrimStart());
                    continue;
                }

                if (_pendingLine != null)
                    writer.TryWrite(_pendingLine);

                _pendingLine = raw;
            }
        }

        // ── Pipeline: consumer side (dedicated background task) ───────────────────

        private async Task ConsumeEntries()
        {
            await foreach (var line in _entryChannel.Reader.ReadAllAsync().ConfigureAwait(false))
                ProcessLine(line);
        }

        private void ProcessLine(string line)
        {
            if (string.IsNullOrEmpty(line)) return;
            if (!PostgreSqlLogParser.TryParse(line, out var pg) || pg is null)
                return;

            // C1: stage host from ConnectionReceived for later correlation
            if (pg.Type == PgLogLineType.ConnectionReceived && pg.Host != null)
            {
                _pidHost[ParsePid(pg.ProcessId)] = pg.Host;
                return;
            }

            // C1: build PID context from ConnectionAuthorized, merging staged host
            if (pg.Type == PgLogLineType.ConnectionAuthorized && pg.User != null)
            {
<<<<<<< Updated upstream
                _pidCtx[ParsePid(pg.ProcessId)] = (pg.User, pg.Database ?? "", pg.Host ?? "");
                return;
            }

            // C1: free PID context on disconnect to bound dictionary growth
            if (pg.Type == PgLogLineType.Disconnection)
            {
                _pidCtx.Remove(ParsePid(pg.ProcessId));
=======
                var pid = ParsePid(pg.ProcessId);
                _pidHost.TryRemove(pid, out var stagedHost);
                _pidCtx[pid] = (pg.User, pg.Database ?? "", stagedHost ?? pg.Host ?? "");
                return;
            }

            // D1: Duration line pairs with the previous Statement for this PID
            if (pg.Type == PgLogLineType.Duration)
            {
                var pid = ParsePid(pg.ProcessId);
                if (_pidPending.TryRemove(pid, out var pending))
                {
                    pending.Entry.Duration = pg.DurationMs ?? 0;
                    EntryDetected?.Invoke(pending.Entry);
                }
>>>>>>> Stashed changes
                return;
            }

            // B3: only run NFA on Statement entries (lines with actual SQL)
            if (pg.Type != PgLogLineType.Statement) return;

            var pid = ParsePid(pg.ProcessId);
            _pidCtx.TryGetValue(pid, out var ctx);

<<<<<<< Updated upstream
            var tokens        = SqlTokenizer.Tokenize(pg.Message);
=======
            // If a previous statement for this PID never got a Duration line, fire it now
            if (_pidPending.TryRemove(pid2, out var orphan))
                EntryDetected?.Invoke(orphan.Entry);

            var tokens        = SqlTokenizer.Tokenize(pg.Message).ToList();
>>>>>>> Stashed changes
            var matchedEngine = RunEngines(tokens);

            // A3: brute-force requires rate confirmation, not just pattern match
            if (matchedEngine?.ThreatType == "BRUTEFORCE")
            {
                var key = $"{ctx.User ?? "unknown"}@{ctx.Host ?? pg.Host ?? "unknown"}";
                if (!IsBruteForce(key)) matchedEngine = null;
            }

            var level = matchedEngine != null
                ? (matchedEngine.Severity ?? pg.Severity).ToUpperInvariant()
                : pg.Severity;

            var entry = new LogEntry
            {
                Timestamp  = pg.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff UTC"),
                Pid        = pid,
                Level      = level,
                UserHost   = $"{ctx.User ?? pg.Identity ?? "unknown"}@{ctx.Host ?? pg.Host ?? "unknown"}",
                Database   = !string.IsNullOrEmpty(ctx.Database) ? ctx.Database : (pg.Database ?? ""),
                Query      = pg.Message,
                Duration   = 0,   // set when Duration line arrives
                IsInjected = matchedEngine != null,
                ThreatType = matchedEngine?.ThreatType ?? ""
            };

            // D1: buffer until paired Duration line fires the entry
            _pidPending[pid2] = (entry, Environment.TickCount64);
        }

        // A3: sliding-window counter per attacker key
        private bool IsBruteForce(string key)
        {
            var now = DateTimeOffset.UtcNow;
            var q   = _bfWindow.GetOrAdd(key, _ => new Queue<DateTimeOffset>());

            lock (q)
            {
                q.Enqueue(now);
                while (q.Count > 0 && now - q.Peek() > BfWindowDuration)
                    q.Dequeue();
                return q.Count >= BfThreshold;
            }
        }

        // M2: returns first matched engine or null.
        // tokenSet is lazily computed and shared across all absent-token checks in one call.
        private NfaEngine? RunEngines(List<string> tokens)
        {
            var engines = _engines; // snapshot — ReloadEngines may swap field concurrently
            if (engines.Count == 0) return null;

            HashSet<string>? tokenSet = null;

            // Sequential path for small engine counts — avoids Parallel.ForEach overhead
            if (engines.Count <= 4)
            {
                foreach (var e in engines)
                {
                    if (!e.Run(tokens)) continue;
                    if (e.RequireAbsentTokens.Count > 0)
                    {
                        tokenSet ??= new HashSet<string>(tokens);
                        bool blocked = false;
                        foreach (var a in e.RequireAbsentTokens)
                            if (tokenSet.Contains(a)) { blocked = true; break; }
                        if (blocked) continue;
                    }
                    return e;
                }
                return null;
            }

            // Parallel path for larger engine sets — pre-compute tokenSet once for all threads
            tokenSet = new HashSet<string>(tokens);
            NfaEngine? found = null;
            Parallel.ForEach(engines, (engine, state) =>
            {
                if (state.ShouldExitCurrentIteration) return;
                if (!engine.Run(tokens)) return;
                if (engine.RequireAbsentTokens.Count > 0)
                {
                    foreach (var a in engine.RequireAbsentTokens)
                        if (tokenSet.Contains(a)) return;
                }
                Interlocked.CompareExchange(ref found, engine, null);
                state.Break();
            });
            return found;
        }

        private static int ParsePid(string s)
            => int.TryParse(s, out var p) ? p : 0;

        public void Dispose()
        {
            _entryChannel.Writer.TryComplete();
            _fileWatcher.Dispose();
        }
    }
}
