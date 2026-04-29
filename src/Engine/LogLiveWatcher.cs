using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using LogGuardV2.src.Model;

namespace LogGuardV2.src.Engine
{
    /// <summary>
    /// Orchestrates live log monitoring:
    ///   FileWatcherLive → PostgreSqlLogParser → SqlTokenizer → NfaEngine[] → LogEntry
    ///
    /// Raises <see cref="EntryDetected"/> on a thread-pool thread.
    /// Callers must dispatch to the UI thread before touching UI objects.
    /// </summary>
    internal sealed class LogLiveWatcher : IDisposable
    {
        private readonly FileWatcherLive _fileWatcher;
        private readonly string          _nfaFolder;
        private List<NfaEngine>          _engines;

        // C1: PID → (User, Database, Host) from ConnectionAuthorized entries
        private readonly Dictionary<int, (string User, string Database, string Host)> _pidCtx = new();

        // A3: brute-force sliding window — key = "user@host"
        private readonly Dictionary<string, Queue<DateTimeOffset>> _bfWindow = new();
        private const int BfThreshold = 5;
        private static readonly TimeSpan BfWindowDuration = TimeSpan.FromMinutes(1);

        // M5: pending multi-line accumulation
        private string? _pendingLine;

        public int EngineCount => _engines.Count;

        public event Action<LogEntry>? EntryDetected;

        public LogLiveWatcher(AppSettings settings, string nfaFolder)
        {
            _nfaFolder             = nfaFolder;
            _engines               = NfaLoader.LoadAll(nfaFolder);
            _fileWatcher           = new FileWatcherLive(
                settings.LogDirectory, settings.WatchPattern, settings.FollowRotation);
            _fileWatcher.NewLines += OnNewLines;
        }

        public void Start(bool replayFromStart = false) => _fileWatcher.Start(replayFromStart);

        // A5: hot reload — swaps engine list atomically
        public void ReloadEngines()
            => Interlocked.Exchange(ref _engines, NfaLoader.LoadAll(_nfaFolder));

        // ── Pipeline ──────────────────────────────────────────────────────────────

        private void OnNewLines(IReadOnlyList<string> lines)
        {
            foreach (var raw in lines)
            {
                // M5: accumulate continuation lines (DETAIL/HINT/CONTEXT)
                if (!PostgreSqlLogParser.LooksLikeHeader(raw))
                {
                    if (_pendingLine != null)
                        _pendingLine += "\n" + raw.TrimStart();
                    continue;
                }

                if (_pendingLine != null)
                    ProcessLine(_pendingLine);

                _pendingLine = raw;
            }
            // Don't flush _pendingLine here — continuation lines may arrive in next batch
        }

        private void ProcessLine(string line)
        {
            if (!PostgreSqlLogParser.TryParse(line, out var pg) || pg is null)
                return;

            // C1: track PID context from connection events
            if (pg.Type == PgLogLineType.ConnectionAuthorized && pg.User != null)
            {
                var pid = ParsePid(pg.ProcessId);
                _pidCtx[pid] = (pg.User, pg.Database ?? "", pg.Host ?? "");
                return;
            }

            // B3: only run NFA on Statement entries (lines with actual SQL)
            if (pg.Type != PgLogLineType.Statement) return;

            var pid2 = ParsePid(pg.ProcessId);
            _pidCtx.TryGetValue(pid2, out var ctx);

            var tokens        = SqlTokenizer.Tokenize(pg.Message).ToList();
            var matchedEngine = RunEngines(tokens);

            // A3: brute-force requires rate confirmation, not just pattern match
            if (matchedEngine?.ThreatType == "BRUTEFORCE")
            {
                var key = $"{ctx.User ?? "unknown"}@{ctx.Host ?? pg.Host ?? "unknown"}";
                if (!IsBruteForce(key)) matchedEngine = null;
            }

            // Use NFA severity for threat entries; pg severity for normal entries
            var level = matchedEngine != null
                ? matchedEngine.Severity.ToUpperInvariant()
                : pg.Severity;

            var entry = new LogEntry
            {
                Timestamp  = pg.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff UTC"),
                Pid        = pid2,
                Level      = level,
                UserHost   = $"{ctx.User ?? pg.Identity ?? "unknown"}@{ctx.Host ?? pg.Host ?? "unknown"}",
                Database   = ctx.Database.Length > 0 ? ctx.Database : (pg.Database ?? ""),
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

        // M2: returns matched engine (carries ThreatType + Severity) or null
        private NfaEngine? RunEngines(List<string> tokens)
        {
            var engines = _engines;
            if (engines.Count == 0) return null;

            if (engines.Count <= 2)
            {
                foreach (var e in engines)
                    if (MatchEngine(e, tokens)) return e;
                return null;
            }

            NfaEngine? found = null;
            Parallel.ForEach(engines, (engine, state) =>
            {
                if (state.ShouldExitCurrentIteration) return;
                if (MatchEngine(engine, tokens))
                {
                    Interlocked.CompareExchange(ref found, engine, null);
                    state.Break();
                }
            });
            return found;
        }

        // A2: post-match absent-token filter for EXFIL and similar profiles
        private static bool MatchEngine(NfaEngine engine, List<string> tokens)
        {
            if (!engine.Run(tokens)) return false;

            if (engine.RequireAbsentTokens.Count > 0)
            {
                var tokenSet = new HashSet<string>(tokens);
                foreach (var absent in engine.RequireAbsentTokens)
                    if (tokenSet.Contains(absent)) return false;
            }

            return true;
        }

        private static int ParsePid(string s)
            => int.TryParse(s, out var p) ? p : 0;

        public void Dispose() => _fileWatcher.Dispose();
    }
}
