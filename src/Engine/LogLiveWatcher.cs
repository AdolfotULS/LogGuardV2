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

        // ── Pipeline: producer side (runs under FileWatcherLive._readLock) ─────────

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
            if (!PostgreSqlLogParser.TryParse(line, out var pg) || pg is null)
                return;

            // C1: track PID context from connection events
            if (pg.Type == PgLogLineType.ConnectionAuthorized && pg.User != null)
            {
                _pidCtx[ParsePid(pg.ProcessId)] = (pg.User, pg.Database ?? "", pg.Host ?? "");
                return;
            }

            // C1: free PID context on disconnect to bound dictionary growth
            if (pg.Type == PgLogLineType.Disconnection)
            {
                _pidCtx.Remove(ParsePid(pg.ProcessId));
                return;
            }

            // B3: only run NFA on Statement entries (lines with actual SQL)
            if (pg.Type != PgLogLineType.Statement) return;

            var pid = ParsePid(pg.ProcessId);
            _pidCtx.TryGetValue(pid, out var ctx);

            var tokens        = SqlTokenizer.Tokenize(pg.Message);
            var matchedEngine = RunEngines(tokens);

            // A3: brute-force requires rate confirmation, not just pattern match
            if (matchedEngine?.ThreatType == "BRUTEFORCE")
            {
                var key = $"{ctx.User ?? "unknown"}@{ctx.Host ?? pg.Host ?? "unknown"}";
                if (!IsBruteForce(key)) matchedEngine = null;
            }

            var level = matchedEngine != null
                ? matchedEngine.Severity.ToUpperInvariant()
                : pg.Severity;

            var entry = new LogEntry
            {
                Timestamp  = pg.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff UTC"),
                Pid        = pid,
                Level      = level,
                UserHost   = $"{ctx.User ?? pg.Identity ?? "unknown"}@{ctx.Host ?? pg.Host ?? "unknown"}",
                Database   = !string.IsNullOrEmpty(ctx.Database) ? ctx.Database : (pg.Database ?? ""),
                Query      = pg.Message,
                Duration   = pg.DurationMs ?? 0,
                IsInjected = matchedEngine != null,
                ThreatType = matchedEngine?.ThreatType ?? ""
            };

            EntryDetected?.Invoke(entry);
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
