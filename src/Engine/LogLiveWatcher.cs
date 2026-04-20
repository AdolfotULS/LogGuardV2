using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using LogGuardV2;

namespace LogGuardV2.src.Engine
{
    /// <summary>
    /// Orchestrates live log monitoring:
    ///   FileWatcherLive → PostgreSqlLogParser → NfaEngine[] (parallel) → LogEntry
    ///
    /// Raises <see cref="EntryDetected"/> on a thread-pool thread for every parsed
    /// log line.  Callers must dispatch to the UI thread before touching UI objects.
    /// </summary>
    internal sealed class LogLiveWatcher : IDisposable
    {
        private readonly FileWatcherLive _fileWatcher;
        private readonly List<NfaEngine> _engines;

        /// <summary>Number of loaded and enabled automaton profiles.</summary>
        public int EngineCount => _engines.Count;

        /// <summary>
        /// Fired for each parsed log entry — may arrive on any thread-pool thread.
        /// </summary>
        public event Action<LogEntry>? EntryDetected;

        public LogLiveWatcher(global::LogGuardV2.AppSettings settings, string nfaFolder)
        {
            _fileWatcher           = new FileWatcherLive(
                settings.LogDirectory, settings.WatchPattern, settings.FollowRotation);
            _fileWatcher.NewLines += OnNewLines;
            _engines               = NfaLoader.LoadAll(nfaFolder);
        }

        public void Start(bool replayFromStart = false)
            => _fileWatcher.Start(replayFromStart);

        // ── Internal pipeline ─────────────────────────────────────────────────────

        private void OnNewLines(IReadOnlyList<string> lines)
        {
            foreach (var line in lines)
            {
                if (!PostgreSqlLogParser.TryParse(line, out var pg) || pg is null)
                    continue;

                var tokens     = SqlTokenizer.Tokenize(pg.Message).ToList();
                var isInjected = RunEnginesParallel(tokens);

                var entry = new LogEntry
                {
                    Timestamp  = pg.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff UTC"),
                    Pid        = int.TryParse(pg.ProcessId, out var pid) ? pid : 0,
                    Level      = pg.Severity,
                    UserHost   = $"{pg.User ?? pg.Identity ?? "unknown"}@{pg.Host ?? "unknown"}",
                    Database   = pg.Database ?? "",
                    Query      = pg.Message,
                    Duration   = pg.DurationMs ?? 0,
                    IsInjected = isInjected
                };

                EntryDetected?.Invoke(entry);
            }
        }

        /// <summary>
        /// Runs all NFA engines against <paramref name="tokens"/>.
        /// Uses Parallel.ForEach for 3+ engines (breaks on first match),
        /// falls back to sequential for 0-2 engines to avoid thread-pool overhead.
        /// NfaEngine.Run() creates no shared state — fully thread-safe.
        /// </summary>
        private bool RunEnginesParallel(List<string> tokens)
        {
            switch (_engines.Count)
            {
                case 0: return false;
                case 1: return _engines[0].Run(tokens);
                case 2: return _engines[0].Run(tokens) || _engines[1].Run(tokens);
            }

            // 3+ engines: true parallel, break on first match
            int detected = 0;
            Parallel.ForEach(_engines, (engine, state) =>
            {
                if (state.ShouldExitCurrentIteration) return;
                if (engine.Run(tokens))
                {
                    Interlocked.Exchange(ref detected, 1);
                    state.Break();
                }
            });
            return detected != 0;
        }

        public void Dispose() => _fileWatcher.Dispose();
    }
}
