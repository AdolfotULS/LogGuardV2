using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using LogGuardV2;

namespace LogGuardV2.src.Engine
{
    /// <summary>
    /// Orchestrates live log monitoring:
    ///   FileWatcherLive → PostgreSqlLogParser → NfaEngine[] → LogEntry
    /// Raises <see cref="EntryDetected"/> (on a thread-pool thread) for every
    /// parsed log line so the UI can display it.
    /// </summary>
    internal sealed class LogLiveWatcher : IDisposable
    {
        private readonly FileWatcherLive  _fileWatcher;
        private readonly List<NfaEngine>  _engines;

        /// <summary>Fired for each parsed log entry. May arrive on any thread — dispatch to UI as needed.</summary>
        public event Action<LogEntry>? EntryDetected;

        public LogLiveWatcher(global::LogGuardV2.AppSettings settings, string nfaFolder)
        {
            _fileWatcher          = new FileWatcherLive(settings.LogDirectory, settings.WatchPattern, settings.FollowRotation);
            _fileWatcher.NewLines += OnNewLines;
            _engines              = NfaLoader.LoadAll(nfaFolder);
        }

        public void Start(bool replayFromStart = false)
            => _fileWatcher.Start(replayFromStart);

        private void OnNewLines(IReadOnlyList<string> lines)
        {
            foreach (var line in lines)
            {
                if (!PostgreSqlLogParser.TryParse(line, out var pg) || pg is null)
                    continue;

                var tokens     = SqlTokenizer.Tokenize(pg.Message).ToList();
                var isInjected = _engines.Any(e => e.Run(tokens));

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

        public void Dispose() => _fileWatcher.Dispose();
    }
}
