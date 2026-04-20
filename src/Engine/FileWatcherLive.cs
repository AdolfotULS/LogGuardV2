using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace LogGuardV2.src.Engine
{
    /// <summary>
    /// Tails a rotating log file and raises <see cref="NewLines"/> for every batch
    /// of appended lines.  Uses a polling timer instead of FileSystemWatcher to
    /// avoid the duplicate-event and buffering quirks on Windows NTFS.
    /// </summary>
    public sealed class FileWatcherLive : IDisposable
    {
        private readonly string _directory;
        private readonly string _pattern;
        private readonly bool   _followRotation;

        private Timer?  _timer;
        private string? _currentFile;
        private long    _offset;
        private readonly object _readLock = new();

        /// <summary>Raised on a thread-pool thread with every new batch of raw log lines.</summary>
        public event Action<IReadOnlyList<string>>? NewLines;

        public FileWatcherLive(string directory, string pattern, bool followRotation)
        {
            _directory      = directory;
            _pattern        = pattern;
            _followRotation = followRotation;
        }

        public void Start(bool replayFromStart)
        {
            _currentFile = FindLatestFile();

            if (_currentFile != null)
                _offset = replayFromStart ? 0L : new FileInfo(_currentFile).Length;

            // Poll every 500 ms — fast enough for near-real-time, cheap on CPU
            _timer = new Timer(Poll, null, TimeSpan.FromMilliseconds(500), TimeSpan.FromMilliseconds(500));
        }

        private void Poll(object? _)
        {
            lock (_readLock)
            {
                if (_followRotation)
                    CheckRotation();

                if (_currentFile != null)
                    ReadTail(_currentFile);
            }
        }

        private void CheckRotation()
        {
            var latest = FindLatestFile();
            if (latest != null && latest != _currentFile)
            {
                _currentFile = latest;
                _offset      = 0;
            }
        }

        private string? FindLatestFile()
        {
            if (!Directory.Exists(_directory)) return null;
            return Directory.GetFiles(_directory, _pattern)
                            .OrderByDescending(f => new FileInfo(f).LastWriteTimeUtc)
                            .FirstOrDefault();
        }

        private void ReadTail(string path)
        {
            try
            {
                using var fs = new FileStream(
                    path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);

                if (fs.Length <= _offset) return;

                fs.Seek(_offset, SeekOrigin.Begin);
                using var reader = new StreamReader(fs, Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false, leaveOpen: true);

                var lines = new List<string>();
                string? line;
                while ((line = reader.ReadLine()) != null)
                    lines.Add(line);

                _offset = fs.Position;

                if (lines.Count > 0)
                    NewLines?.Invoke(lines);
            }
            catch
            {
                // File may be locked during rotation — next poll will retry
            }
        }

        public void Stop()  => _timer?.Change(Timeout.Infinite, Timeout.Infinite);
        public void Dispose() { _timer?.Dispose(); }
    }
}
