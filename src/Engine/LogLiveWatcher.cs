using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using LogGuardV2.src.Model;

namespace LogGuardV2.src.Engine
{
    /// <summary>
    /// Orchestrates live log monitoring:
    ///   FileWatcherLive -> PostgreSqlLogParser -> SqlTokenizer -> NfaEngine[] -> LogEntry
    ///
    /// File I/O and NFA processing are decoupled via a Channel. OnNewLines (called
    /// under the file-watcher lock) accumulates multi-line entries and enqueues them;
    /// a dedicated consumer task performs all CPU-heavy work independently.
    ///
    /// Raises EntryDetected on the consumer task thread.
    /// Callers must dispatch to the UI thread before touching UI objects.
    /// </summary>
    internal sealed class LogLiveWatcher : IDisposable
    {
        private readonly FileWatcherLive _fileWatcher;
        private readonly string          _nfaFolder;
        private List<NfaEngine>          _engines;

        // AllowSynchronousContinuations = false: prevents reader from running inline on writer thread.
        // SingleWriter = false: FlushStale (UI thread) and OnNewLines (timer thread) both write.
        private readonly Channel<string> _entryChannel = Channel.CreateUnbounded<string>(
            new UnboundedChannelOptions
            {
                SingleReader                  = true,
                SingleWriter                  = false,
                AllowSynchronousContinuations = false
            });
        private readonly Task _consumer;

        // All dictionaries: consumer-task-only access (single reader), plain Dictionary safe.

        // C1: PID -> (User, Database, Host) built from ConnectionAuthorized
        private readonly Dictionary<int, (string User, string Database, string Host)> _pidCtx = new();

        // C1: host staging - stored on ConnectionReceived, merged into _pidCtx on ConnectionAuthorized
        private readonly Dictionary<int, string> _pidHost = new();

        // D1: Statement entry buffered per PID awaiting its paired Duration line
        private readonly Dictionary<int, (LogEntry Entry, long CreatedTick)> _pidPending = new();

        // A3: brute-force sliding window
        private readonly Dictionary<string, Queue<DateTimeOffset>> _bfWindow = new();
        private const int BfThreshold = 5;
        private static readonly TimeSpan BfWindowDuration = TimeSpan.FromMinutes(1);

        // M5: multi-line accumulation - only accessed from OnNewLines (under file-watcher lock)
        private string? _pendingLine;

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

        // A5: hot reload - swaps engine list atomically
        public void ReloadEngines()
            => Interlocked.Exchange(ref _engines, NfaLoader.LoadAll(_nfaFolder));

        // D1: flush pending entries older than maxAgeMs that never received a Duration line.
        // Called from UI thread (RefreshKpis) - safe because SingleWriter = false.
        public void FlushStale(long maxAgeMs = 2000)
            => _entryChannel.Writer.TryWrite($"\x00FLUSH:{maxAgeMs}");

        // -- Pipeline: producer side (runs under FileWatcherLive._readLock) -------

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

            // Flush the last pending line at end of every batch.
            // PostgreSQL Duration lines have no continuations so this is safe.
            // Without this flush, Duration lines stay stuck until the next batch arrives,
            // preventing statement entries from ever firing.
            if (_pendingLine != null)
            {
                writer.TryWrite(_pendingLine);
                _pendingLine = null;
            }
        }

        // -- Pipeline: consumer side (dedicated background task) ------------------

        private async Task ConsumeEntries()
        {
            await foreach (var line in _entryChannel.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                try
                {
                    if (line.StartsWith("\x00FLUSH:", StringComparison.Ordinal))
                    {
                        if (long.TryParse(line.AsSpan(7), out var maxAge))
                            DoFlushStale(maxAge);
                    }
                    else
                    {
                        ProcessLine(line);
                    }
                }
                catch
                {
                    // Swallow per-line exceptions - consumer task must never die.
                }
            }
        }

        private void DoFlushStale(long maxAgeMs)
        {
            var now     = Environment.TickCount64;
            var toEvict = new List<(int Pid, LogEntry Entry)>();

            foreach (var kvp in _pidPending)
            {
                if (now - kvp.Value.CreatedTick >= maxAgeMs)
                    toEvict.Add((kvp.Key, kvp.Value.Entry));
            }

            foreach (var (pid, entry) in toEvict)
            {
                _pidPending.Remove(pid);
                EntryDetected?.Invoke(entry);
            }
        }

        private void ProcessLine(string line)
        {
            if (string.IsNullOrEmpty(line)) return;
            if (!PostgreSqlLogParser.TryParse(line, out var pg) || pg is null) return;

            // C1: stage host from ConnectionReceived for later correlation
            if (pg.Type == PgLogLineType.ConnectionReceived && pg.Host != null)
            {
                _pidHost[ParsePid(pg.ProcessId)] = pg.Host;
                return;
            }

            // C1: build PID context from ConnectionAuthorized, merging staged host
            if (pg.Type == PgLogLineType.ConnectionAuthorized && pg.User != null)
            {
                var pid = ParsePid(pg.ProcessId);
                _pidHost.Remove(pid, out var stagedHost);
                _pidCtx[pid] = (pg.User, pg.Database ?? "", stagedHost ?? pg.Host ?? "");
                return;
            }

            // C1: free PID context on disconnect to bound dictionary growth
            if (pg.Type == PgLogLineType.Disconnection)
            {
                var pid = ParsePid(pg.ProcessId);
                _pidCtx.Remove(pid);
                _pidHost.Remove(pid);
                _pidPending.Remove(pid);
                return;
            }

            // D1: Duration line pairs with the preceding Statement for this PID
            if (pg.Type == PgLogLineType.Duration)
            {
                var pid = ParsePid(pg.ProcessId);
                if (_pidPending.Remove(pid, out var pending))
                {
                    pending.Entry.Duration = pg.DurationMs ?? 0;
                    EntryDetected?.Invoke(pending.Entry);
                }
                return;
            }

            // B3: only run NFA on Statement entries (lines with actual SQL)
            if (pg.Type != PgLogLineType.Statement) return;

            var pid2 = ParsePid(pg.ProcessId);
            _pidCtx.TryGetValue(pid2, out var ctx);

            // If a previous statement for this PID never got a Duration line, fire it now
            if (_pidPending.Remove(pid2, out var orphan))
                EntryDetected?.Invoke(orphan.Entry);

            var tokens        = SqlTokenizer.Tokenize(pg.Message);
            var matchedEngine = RunEngines(tokens);

            // A3: brute-force requires rate confirmation, not just pattern match
            if (matchedEngine?.ThreatType == "BRUTEFORCE")
            {
                var key = $"{ctx.User ?? "unknown"}@{ctx.Host ?? pg.Host ?? "unknown"}";
                if (!IsBruteForce(key)) matchedEngine = null;
            }

            var level = matchedEngine != null
                ? (!string.IsNullOrEmpty(matchedEngine.Severity) ? matchedEngine.Severity : pg.Severity).ToUpperInvariant()
                : pg.Severity;

            var entry = new LogEntry
            {
                Timestamp  = pg.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff UTC"),
                Pid        = pid2,
                Level      = level,
                UserHost   = $"{ctx.User ?? pg.User ?? pg.Identity ?? "unknown"}@{ctx.Host ?? pg.Host ?? "unknown"}",
                Database   = !string.IsNullOrEmpty(ctx.Database) ? ctx.Database : (!string.IsNullOrEmpty(pg.Database) ? pg.Database : ""),
                Query      = pg.Message,
                Duration   = 0,   // populated when the matching Duration line arrives
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
            if (!_bfWindow.TryGetValue(key, out var q))
                _bfWindow[key] = q = new Queue<DateTimeOffset>();

            q.Enqueue(now);
            while (q.Count > 0 && now - q.Peek() > BfWindowDuration)
                q.Dequeue();
            return q.Count >= BfThreshold;
        }

        // M2: returns first matched engine or null.
        // tokenSet is lazily computed and shared across all absent-token checks in one call.
        private NfaEngine? RunEngines(List<string> tokens)
        {
            var engines = _engines; // snapshot - ReloadEngines may swap field concurrently
            if (engines.Count == 0) return null;

            HashSet<string>? tokenSet = null;

            // Sequential path for small engine counts
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

            // Parallel path for larger engine sets - pre-compute tokenSet once for all threads
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