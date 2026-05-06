using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace LogGuardV2.src.Engine
{
    /// <summary>
    /// Tails a rotating log file and raises <see cref="NewLines"/> for every batch
    /// of appended lines.  Uses a polling timer instead of FileSystemWatcher to
    /// avoid the duplicate-event and buffering quirks on Windows NTFS.
    /// Keeps the FileStream open between polls to avoid repeated open/close overhead.
    /// </summary>
    public sealed class FileWatcherLive : IDisposable
    {
        private readonly string _directory;
        private readonly string _pattern;
        private readonly bool   _followRotation;

        private Timer?       _timer;
        private string?      _currentFile;
        private long         _offset;
        private FileStream?  _fileStream;
        private StreamReader? _reader;
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
            {
                var initialOffset = replayFromStart ? 0L : new FileInfo(_currentFile).Length;
                OpenFile(_currentFile, initialOffset);
            }
            _timer = new Timer(Poll, null, TimeSpan.FromMilliseconds(500), TimeSpan.FromMilliseconds(500));
        }

        private void Poll(object? _)
        {
            lock (_readLock)
            {
                if (_followRotation)
                    CheckRotation();
                if (_currentFile != null)
                    ReadTail();
            }
        }

        private void CheckRotation()
        {
            var latest = FindLatestFile();
            if (latest != null && latest != _currentFile)
            {
                _currentFile = latest;
                OpenFile(latest, 0);
            }
        }

        private void OpenFile(string path, long offset)
        {
            DisposeStream();
            try
            {
                _fileStream = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, bufferSize: 65536);
                _fileStream.Seek(offset, SeekOrigin.Begin);
                _reader = new StreamReader(_fileStream, Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false, leaveOpen: true);
                _offset = offset;
            }
            catch
            {
                DisposeStream();
            }
        }

        private void DisposeStream()
        {
            _reader?.Dispose();     _reader     = null;
            _fileStream?.Dispose(); _fileStream = null;
        }

        private string? FindLatestFile()
        {
            if (!Directory.Exists(_directory)) return null;
            var files = Directory.GetFiles(_directory, _pattern);
            if (files.Length == 0) return null;
            string? best    = null;
            var     bestUtc = DateTime.MinValue;
            foreach (var f in files)
            {
                var t = File.GetLastWriteTimeUtc(f);
                if (t > bestUtc) { bestUtc = t; best = f; }
            }
            return best;
        }

        private void ReadTail()
        {
            if (_fileStream == null || _reader == null) return;
            try
            {
                var lines = new List<string>(32);
                string? line;
                while ((line = _reader.ReadLine()) != null)
                    lines.Add(line);

                _offset = _fileStream.Position;

                if (lines.Count > 0)
                    NewLines?.Invoke(lines);
            }
            catch
            {
                // File locked or rotated mid-read — reopen from last good offset on next poll
                OpenFile(_currentFile!, _offset);
            }
        }

        public void Stop()    => _timer?.Change(Timeout.Infinite, Timeout.Infinite);

        public void Dispose()
        {
            _timer?.Dispose();
            DisposeStream();
        }
    }
}
