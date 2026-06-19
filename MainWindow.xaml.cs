using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using System.Text.Json;
using System.Text.Json.Nodes;
using LogGuardV2.src.Engine;
using LogGuardV2.src.Model;
using Microsoft.Win32;

namespace LogGuardV2
{
    // ─── Value converters ────────────────────────────────────────────────────────

    public class LevelToSevColorConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "CRITICAL" or "FATAL" or "ERROR" => Application.Current.Resources["DangerBrush"],
            "HIGH"     or "WARNING"          => Application.Current.Resources["WarnBrush"],
            "MEDIUM"   or "NOTICE"           => Application.Current.Resources["InfoBrush"],
            "LOW"                            => Application.Current.Resources["TextMuteBrush"],
            _                                => Application.Current.Resources["OkBrush"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class LevelToBadgeFgConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "CRITICAL" or "FATAL"   => Brushes.White,
            "HIGH"     or "ERROR"   => Application.Current.Resources["DangerBrush"],
            "MEDIUM"   or "WARNING" => Application.Current.Resources["WarnBrush"],
            "LOW"      or "NOTICE"  => Application.Current.Resources["InfoBrush"],
            _                       => Application.Current.Resources["TextMuteBrush"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class LevelToBadgeBgConverter : IValueConverter
    {
        private static readonly SolidColorBrush _highBg   = FB(new SolidColorBrush(Color.FromArgb(20,  229, 72,  77)));
        private static readonly SolidColorBrush _warnBg   = FB(new SolidColorBrush(Color.FromArgb(20,  245, 158, 11)));
        private static readonly SolidColorBrush _noticeBg = FB(new SolidColorBrush(Color.FromArgb(20,  139, 92,  246)));
        private static SolidColorBrush FB(SolidColorBrush b) { b.Freeze(); return b; }
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "CRITICAL" or "FATAL"   => Application.Current.Resources["DangerBrush"],
            "HIGH"     or "ERROR"   => _highBg,
            "MEDIUM"   or "WARNING" => _warnBg,
            "LOW"      or "NOTICE"  => _noticeBg,
            _                       => Application.Current.Resources["Bg2"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class LevelToBadgeBorderConverter : IValueConverter
    {
        private static readonly SolidColorBrush _highBrd   = FB(new SolidColorBrush(Color.FromArgb(100, 229, 72,  77)));
        private static readonly SolidColorBrush _warnBrd   = FB(new SolidColorBrush(Color.FromArgb(100, 245, 158, 11)));
        private static readonly SolidColorBrush _noticeBrd = FB(new SolidColorBrush(Color.FromArgb(100, 139, 92,  246)));
        private static SolidColorBrush FB(SolidColorBrush b) { b.Freeze(); return b; }
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "CRITICAL" or "FATAL"   => Application.Current.Resources["DangerBrush"],
            "HIGH"     or "ERROR"   => _highBrd,
            "MEDIUM"   or "WARNING" => _warnBrd,
            "LOW"      or "NOTICE"  => _noticeBrd,
            _                       => Application.Current.Resources["Line2Brush"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class BoolToInjTextConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (bool)v ? "● YES" : "—";
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class BoolToInjFgConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) =>
            (bool)v ? Application.Current.Resources["DangerBrush"]
                    : Application.Current.Resources["TextMuteBrush"];
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class BoolToInjBgConverter : IValueConverter
    {
        private static readonly SolidColorBrush _injBg = FB(new SolidColorBrush(Color.FromArgb(20, 229, 72, 77)));
        private static SolidColorBrush FB(SolidColorBrush b) { b.Freeze(); return b; }
        public object Convert(object v, Type t, object p, CultureInfo c) =>
            (bool)v ? (object)_injBg : Application.Current.Resources["Bg2"];
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class BoolToInjBorderConverter : IValueConverter
    {
        private static readonly SolidColorBrush _injBrd = FB(new SolidColorBrush(Color.FromArgb(100, 229, 72, 77)));
        private static SolidColorBrush FB(SolidColorBrush b) { b.Freeze(); return b; }
        public object Convert(object v, Type t, object p, CultureInfo c) =>
            (bool)v ? (object)_injBrd : Application.Current.Resources["Line2Brush"];
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class DurFmtConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => ((double)v).ToString("F1");
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    // ─── MainWindow ──────────────────────────────────────────────────────────────

    public partial class MainWindow : Window
    {
        private readonly ObservableCollection<LogEntry> _entries = new();
        private System.ComponentModel.ICollectionView? _view;
        private string _searchText = "";
        private readonly HashSet<string> _activeFilters = new() { "CRITICAL","HIGH","MEDIUM","LOW","WARNING","LOG" };
        private readonly Dictionary<string, int> _levelCounts = new(5) { ["LOG"]=0, ["NOTICE"]=0, ["WARNING"]=0, ["ERROR"]=0, ["CRITICAL"]=0 };

        private readonly DispatcherTimer _clock   = new();
        private readonly DispatcherTimer _kpiTimer = new();
        private LogLiveWatcher? _liveWatcher;
        private bool _isWatching;
        private readonly DateTime _appStart = DateTime.UtcNow;
        private AppSettings _currentSettings = new();
        private System.Windows.Forms.NotifyIcon? _trayIcon;

        // Counters — written on thread-pool, read on UI thread via Interlocked
        private long _totalEvents;
        private long _fatalErrorCount;
        private long _injectedCount;
        private long _durationSumUs;   // microseconds for precision; avoids (long)double truncation
        private long _durationCount;   // entries with non-zero duration (denominator for avg)
        private long _eventsThisSecond;
        private long _injectedThisSecond;
        private long _fatalThisSecond;

        // Fatal-per-minute sliding window — written on thread-pool under lock
        private readonly Queue<DateTimeOffset> _fatalMinWindow = new();
        private readonly object _fatalWindowLock = new();

        // Sparkline history (48 points, 1s each)
        private readonly System.Collections.Generic.Queue<double> _epsHistory  = new();
        private readonly System.Collections.Generic.Queue<double> _injHistory  = new();
        private readonly System.Collections.Generic.Queue<double> _fatHistory  = new();
        private readonly System.Collections.Generic.Queue<double> _durHistory  = new();
        private const int SparkPoints = 48;

        // Static frozen-brush cache — keyed by hex string, eliminates per-tick allocations
        private static readonly Dictionary<string, (Color C, SolidColorBrush Solid, SolidColorBrush Fill36, SolidColorBrush Fill89, SolidColorBrush Fill178)> _brushCache = new();
        private static (Color C, SolidColorBrush Solid, SolidColorBrush Fill36, SolidColorBrush Fill89, SolidColorBrush Fill178) GetBrush(string hex)
        {
            if (!_brushCache.TryGetValue(hex, out var e))
            {
                var c   = (Color)ColorConverter.ConvertFromString(hex);
                var s   = Frz(new SolidColorBrush(c));
                var f36 = Frz(new SolidColorBrush(Color.FromArgb( 36, c.R, c.G, c.B)));
                var f89 = Frz(new SolidColorBrush(Color.FromArgb( 89, c.R, c.G, c.B)));
                var f178= Frz(new SolidColorBrush(Color.FromArgb(178, c.R, c.G, c.B)));
                _brushCache[hex] = e = (c, s, f36, f89, f178);
            }
            return e;
        }
        private static SolidColorBrush Frz(SolidColorBrush b) { b.Freeze(); return b; }

        public MainWindow()
        {
            InitializeComponent();
            _view = System.Windows.Data.CollectionViewSource.GetDefaultView(_entries);
            // ICollectionView is System.ComponentModel.ICollectionView
            _view.Filter = FilterEntry;
            LogGrid.ItemsSource = _view;
            LoadData();
            LoadSettingsToForm();
            SetupClock();
            SetupKpiTimer();
            Loaded += (_, _) => DrawCharts();
            Closed += (_, _) => { StopWatcher(); _trayIcon?.Dispose(); };

            _trayIcon = new System.Windows.Forms.NotifyIcon
            {
                Icon    = System.Drawing.SystemIcons.Shield,
                Text    = "LogGuardV2",
                Visible = false
            };
        }

        // ─── Watcher lifecycle ────────────────────────────────────────────────────

        private void BtnStart_Click(object s, RoutedEventArgs e) => StartWatcher();
        private void BtnStop_Click(object s, RoutedEventArgs e)  => StopWatcher();

        private void StartWatcher()
        {
            if (_isWatching) return;

            // Fix: clear previous session to prevent duplication on restart
            _entries.Clear();
            Interlocked.Exchange(ref _totalEvents,      0);
            Interlocked.Exchange(ref _fatalErrorCount,  0);
            Interlocked.Exchange(ref _injectedCount,    0);
            Interlocked.Exchange(ref _durationSumUs,    0);
            Interlocked.Exchange(ref _durationCount,    0);
            Interlocked.Exchange(ref _eventsThisSecond,   0);
            Interlocked.Exchange(ref _injectedThisSecond, 0);
            Interlocked.Exchange(ref _fatalThisSecond,    0);
            lock (_fatalWindowLock) _fatalMinWindow.Clear();

            var settings  = ReadSettingsFromForm();
            var nfaFolder = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "NFA");

            _currentSettings = settings;
            if (_trayIcon != null) _trayIcon.Visible = settings.DesktopNotifications;

            _liveWatcher?.Dispose();
            _liveWatcher = new LogLiveWatcher(settings, nfaFolder);
            _liveWatcher.EntryDetected += OnLiveEntry;
            _liveWatcher.Start(settings.ReplayOnStart);

            _isWatching = true;
            SetWatcherUi(running: true, settings.WatchPattern, _liveWatcher.EngineCount);
        }

        private void StopWatcher()
        {
            _liveWatcher?.Dispose();
            _liveWatcher = null;
            _isWatching  = false;

            Dispatcher.InvokeAsync(() =>
                SetWatcherUi(running: false));
        }

        private void SetWatcherUi(bool running, string pattern = "", int engineCount = 0)
        {
            BtnStart.IsEnabled         = !running;
            BtnStop.IsEnabled          =  running;
            StatusDot.Fill             = (Brush)FindResource(running ? "OkBrush" : "WarnBrush");
            ModulesActiveBadge.Text    = running
                ? $"{engineCount} / {engineCount} MODULES ACTIVE"
                : "0 / 0 MODULES ACTIVE";
            StatusText.Text = running
                ? $"LIVE · {pattern} │ events: 0 │ modules: {engineCount}"
                : "STOPPED · configure source in Settings then click Start";
        }

        private const int MaxEntries = 5_000;

        private void OnLiveEntry(LogEntry entry)
        {
            Interlocked.Increment(ref _totalEvents);
            Interlocked.Increment(ref _eventsThisSecond);
            if (entry.Level is "CRITICAL" or "FATAL" or "HIGH" or "ERROR")
            {
                Interlocked.Increment(ref _fatalErrorCount);
                Interlocked.Increment(ref _fatalThisSecond);
                lock (_fatalWindowLock)
                {
                    var now = DateTimeOffset.UtcNow;
                    _fatalMinWindow.Enqueue(now);
                    while (_fatalMinWindow.Count > 0 && now - _fatalMinWindow.Peek() > TimeSpan.FromMinutes(1))
                        _fatalMinWindow.Dequeue();
                }
            }
            if (entry.IsInjected)
            {
                Interlocked.Increment(ref _injectedCount);
                Interlocked.Increment(ref _injectedThisSecond);
            }

            // Desktop notifications — safe to call from thread-pool via Dispatcher
            if (_currentSettings.AudioBeepOnFatal && entry.Level is "CRITICAL" or "FATAL")
                ThreadPool.UnsafeQueueUserWorkItem(_ => Console.Beep(880, 300), null);

            if (_currentSettings.DesktopNotifications && entry.IsInjected && _trayIcon is not null)
                Dispatcher.InvokeAsync(() =>
                    _trayIcon.ShowBalloonTip(4000,
                        "LogGuard — Amenaza detectada",
                        $"{entry.ThreatType} · {entry.UserHost} · {entry.Database}",
                        System.Windows.Forms.ToolTipIcon.Warning));

            if (entry.Duration > 0)
            {
                Interlocked.Add(ref _durationSumUs, (long)(entry.Duration * 1000));
                Interlocked.Increment(ref _durationCount);
            }

            Dispatcher.InvokeAsync(() =>
            {
                _entries.Insert(0, entry);
                if (_entries.Count > MaxEntries)
                    _entries.RemoveAt(_entries.Count - 1);
            });
        }

        // ─── KPI refresh (every 1 s on UI thread) ─────────────────────────────────

        private void SetupKpiTimer()
        {
            _kpiTimer.Interval = TimeSpan.FromSeconds(1);
            _kpiTimer.Tick    += (_, _) => RefreshKpis();
            _kpiTimer.Start();
        }

        private void RefreshKpis()
        {
            _liveWatcher?.FlushStale();

            var eps      = Interlocked.Exchange(ref _eventsThisSecond,   0);
            var epsInj   = Interlocked.Exchange(ref _injectedThisSecond, 0);
            var epsFat   = Interlocked.Exchange(ref _fatalThisSecond,    0);
            var total    = Interlocked.Read(ref _totalEvents);
            var errors   = Interlocked.Read(ref _fatalErrorCount);
            var injected = Interlocked.Read(ref _injectedCount);
            var durSumUs = Interlocked.Read(ref _durationSumUs);
            var durCount = Interlocked.Read(ref _durationCount);
            var avg      = durCount > 0 ? durSumUs / 1000.0 / durCount : 0.0;
            var uptime   = DateTime.UtcNow - _appStart;

            KpiEventsPerSec.Text = eps.ToString("N0");
            KpiFatalError.Text   = errors.ToString("N0");
            KpiInjected.Text     = injected.ToString("N0");
            KpiAvgDuration.Text  = avg.ToString("F1");
            KpiUptime.Text       = uptime.ToString(@"hh\:mm\:ss");

            // ── KPI alert subtexts ────────────────────────────────────────────────

            // EPS: trend vs 5m avg
            if (_epsHistory.Count >= 2)
            {
                double avg5m    = _epsHistory.Average();
                double delta    = eps - avg5m;
                string arrow    = delta > 0 ? "▴" : delta < 0 ? "▾" : "—";
                string pct      = avg5m > 0 ? $"{Math.Abs(delta / avg5m * 100):F0}%" : "—";
                KpiEpsSubtext.Foreground = (Brush)(delta > avg5m * 0.5
                    ? FindResource("WarnBrush") : FindResource("OkBrush"));
                KpiEpsSubtext.Text = $"{arrow} {pct} vs 5m avg";
            }
            else
            {
                KpiEpsSubtext.Text = "— vs 5m avg";
                KpiEpsSubtext.Foreground = (Brush)FindResource("OkBrush");
            }

            // Fatal: count in last 60s from sliding window
            int fatalLastMin;
            lock (_fatalWindowLock)
            {
                var now = DateTimeOffset.UtcNow;
                while (_fatalMinWindow.Count > 0 && now - _fatalMinWindow.Peek() > TimeSpan.FromMinutes(1))
                    _fatalMinWindow.Dequeue();
                fatalLastMin = _fatalMinWindow.Count;
            }
            KpiFatalSubtext.Text = fatalLastMin == 0
                ? "0 in last min"
                : $"▴ {fatalLastMin} in last min";
            KpiFatalSubtext.Foreground = (Brush)FindResource(fatalLastMin >= 10 ? "DangerBrush"
                : fatalLastMin >= 3 ? "WarnBrush" : "OkBrush");

            // Injected: total + rate context
            KpiInjSubtext.Text = $"{injected:N0} total · session";
            KpiInjSubtext.Foreground = (Brush)FindResource(injected >= 10 ? "DangerBrush"
                : injected >= 1 ? "WarnBrush" : "TextMuteBrush");

            // Duration: sort once; pass snapshot to RefreshDashboardCharts and DrawLatencyHistogram
            double[] durSnapshot = _entries.Select(e => e.Duration).Where(d => d > 0).ToArray();
            if (durSnapshot.Length >= 5) Array.Sort(durSnapshot);
            double[]? sortedDurations = durSnapshot.Length >= 5 ? durSnapshot : null;

            if (sortedDurations != null)
            {
                double p95 = sortedDurations[(int)(sortedDurations.Length * 0.95)];
                KpiDurSubtext.Text = $"p95 {p95:F0}ms";
                KpiDurSubtext.Foreground = (Brush)FindResource(p95 >= 1000 ? "DangerBrush"
                    : p95 >= 200 ? "WarnBrush" : "TextMuteBrush");
            }
            else
            {
                KpiDurSubtext.Text = "p95 —ms";
                KpiDurSubtext.Foreground = (Brush)FindResource("TextMuteBrush");
            }

            // Uptime: start time
            KpiUptimeSubtext.Text = $"since {_appStart:HH:mm} UTC";

            PushHistory(_epsHistory, eps);
            PushHistory(_injHistory, epsInj);
            PushHistory(_fatHistory, epsFat);
            PushHistory(_durHistory, avg);

            if (_isWatching && _liveWatcher != null)
                StatusText.Text =
                    $"LIVE · events: {total:N0} │ injected: {injected:N0} │ modules: {_liveWatcher.EngineCount}";

            RefreshDashboardCharts(eps, epsInj, epsFat, avg, total, errors, injected, sortedDurations);
        }

        private static void PushHistory(System.Collections.Generic.Queue<double> q, double v)
        {
            q.Enqueue(v);
            while (q.Count > SparkPoints) q.Dequeue();
        }

        private void RefreshDashboardCharts(double eps, double epsInj, double epsFat, double avg,
                                            long total, long errors, long injected, double[]? sortedDurations = null)
        {
            DashQpsValue.Text    = eps.ToString("N0");
            DashInjValue.Text    = epsInj.ToString("N0");
            DashFatalValue.Text  = epsFat.ToString("N0");
            DashAvgDurValue.Text = avg.ToString("F1");

            double peakEps = _epsHistory.Count > 0 ? _epsHistory.Max() : 0;
            double avgEps  = _epsHistory.Count > 0 ? _epsHistory.Average() : 0;
            DashQpsDetail.Text   = $"peak {peakEps:N0} · avg {avgEps:N0}";
            DashInjDetail.Text   = $"total: {injected:N0} · session";
            DashFatalDetail.Text = $"total: {errors:N0} · session";

            if (sortedDurations != null && sortedDurations.Length >= 10)
            {
                double p95 = sortedDurations[(int)(sortedDurations.Length * 0.95)];
                double p99 = sortedDurations[(int)(sortedDurations.Length * 0.99)];
                DashAvgDurDetail.Text = $"p95 {p95:F0}ms · p99 {p99:F0}ms";
                LatencyStatsText.Text = $"p50 {sortedDurations[sortedDurations.Length / 2]:F0}ms · p95 {p95:F0}ms · p99 {p99:F0}ms";
            }
            else
            {
                DashAvgDurDetail.Text = "p95 —ms · p99 —ms";
                LatencyStatsText.Text = "p50 —ms · p95 —ms · p99 —ms";
            }

            if (TabDashboard.Visibility == Visibility.Visible)
            {
                DrawSparkline(SparkQps,      "#4F8CFF", _epsHistory);
                DrawSparkline(SparkInjected, "#F59E0B", _injHistory);
                DrawSparkline(SparkFatal,    "#E5484D", _fatHistory);
                DrawSparkline(SparkAvgDur,   "#8B5CF6", _durHistory);

                DrawLevelDistribution();
                DrawTopDatabases();
                DrawLatencyHistogram(sortedDurations);
            }
        }

        // ─── Settings ─────────────────────────────────────────────────────────────

        private void LoadSettingsToForm()
        {
            var s = SettingsService.Load();
            TxtLogDir.Text               = s.LogDirectory;
            TxtWatchPattern.Text         = s.WatchPattern;
            TxtTimezone.Text             = s.Timezone;
            TxtLogLineFormat.Text        = s.LogLineFormat;
            TogFollowRotation.IsChecked  = s.FollowRotation;
            TogReplayOnStart.IsChecked   = s.ReplayOnStart;
            TogCoreFields.IsChecked      = s.ParseCoreFields;
            TogConnectionDetails.IsChecked = s.ParseConnectionDetails;
            TogQueryDetails.IsChecked    = s.ParseQueryDetails;
            TogSystemMetrics.IsChecked   = s.ParseSystemMetrics;
            TogRawMessage.IsChecked      = s.ParseRawMessage;
            TogRedactPasswords.IsChecked = s.RedactPasswords;
            TxtWebhookUrl.Text                  = s.AlertWebhookUrl;
            TxtMinLevel.Text                    = s.AlertMinLevel;
            TogDesktopNotifications.IsChecked   = s.DesktopNotifications;
            TogAudioBeepOnFatal.IsChecked        = s.AudioBeepOnFatal;
        }

        private AppSettings ReadSettingsFromForm() => new()
        {
            LogDirectory           = TxtLogDir.Text.Trim(),
            WatchPattern           = TxtWatchPattern.Text.Trim(),
            Timezone               = TxtTimezone.Text.Trim(),
            LogLineFormat          = TxtLogLineFormat.Text,
            FollowRotation         = TogFollowRotation.IsChecked    == true,
            ReplayOnStart          = TogReplayOnStart.IsChecked     == true,
            ParseCoreFields        = TogCoreFields.IsChecked        == true,
            ParseConnectionDetails = TogConnectionDetails.IsChecked == true,
            ParseQueryDetails      = TogQueryDetails.IsChecked      == true,
            ParseSystemMetrics     = TogSystemMetrics.IsChecked     == true,
            ParseRawMessage        = TogRawMessage.IsChecked        == true,
            RedactPasswords        = TogRedactPasswords.IsChecked   == true,
            AlertWebhookUrl        = TxtWebhookUrl.Text.Trim(),
            AlertMinLevel          = TxtMinLevel.Text.Trim(),
            DesktopNotifications   = TogDesktopNotifications.IsChecked == true,
            AudioBeepOnFatal       = TogAudioBeepOnFatal.IsChecked     == true
        };

        private void BtnSaveSettings_Click(object s, RoutedEventArgs e)
        {
            var settings = ReadSettingsFromForm();
            SettingsService.Save(settings);

            // Restart watcher with new settings if currently running
            if (_isWatching)
            {
                StopWatcher();
                Dispatcher.InvokeAsync(StartWatcher, DispatcherPriority.Background);
            }
        }

        private void BtnDiscardSettings_Click(object s, RoutedEventArgs e) => LoadSettingsToForm();

        private void BtnBrowseLogDir_Click(object s, RoutedEventArgs e)
        {
            var dlg = new OpenFolderDialog
            {
                Title            = "Select PostgreSQL log directory",
                InitialDirectory = TxtLogDir.Text.Trim()
            };
            if (dlg.ShowDialog() == true)
                TxtLogDir.Text = dlg.FolderName;
        }

        private void BtnTestPattern_Click(object s, RoutedEventArgs e)
        {
            var dir = TxtLogDir.Text.Trim();
            var pat = TxtWatchPattern.Text.Trim();

            if (!System.IO.Directory.Exists(dir))
            {
                MessageBox.Show($"Directory not found:\n{dir}", "Pattern Test",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var matches = System.IO.Directory.GetFiles(dir, pat);
            MessageBox.Show(
                matches.Length == 0
                    ? $"No files match '{pat}' in:\n{dir}"
                    : $"{matches.Length} file(s) match '{pat}':\n{string.Join("\n", matches.Take(8))}",
                "Pattern Test", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        // ─── Discord webhook test ─────────────────────────────────────────────────

        private static readonly System.Net.Http.HttpClient _http = new();

        private async void BtnTestWebhook_Click(object s, RoutedEventArgs e)
        {
            var url = TxtWebhookUrl.Text.Trim();
            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show("Ingresa una URL de webhook antes de probar.", "Test Webhook",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            BtnTestWebhook.IsEnabled = false;
            BtnTestWebhook.Content   = "ENVIANDO…";

            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                username = "LogGuardV2",
                embeds   = new[]
                {
                    new
                    {
                        title       = "Test de webhook — LogGuardV2",
                        description = "Webhook configurado correctamente. Las alertas de amenazas se enviarán aquí.",
                        color       = 3066993,   // verde Discord
                        footer      = new { text = $"Enviado: {DateTime.Now:yyyy-MM-dd HH:mm:ss}" }
                    }
                }
            });

            try
            {
                var content  = new System.Net.Http.StringContent(payload, System.Text.Encoding.UTF8, "application/json");
                var response = await _http.PostAsync(url, content);

                if (response.IsSuccessStatusCode)
                {
                    BtnTestWebhook.Content = "OK — MENSAJE ENVIADO";
                    await System.Threading.Tasks.Task.Delay(3000);
                }
                else
                {
                    var body = await response.Content.ReadAsStringAsync();
                    MessageBox.Show($"Discord rechazó la solicitud.\nHTTP {(int)response.StatusCode}: {body}",
                        "Test Webhook", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error al conectar con el webhook:\n{ex.Message}",
                    "Test Webhook", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnTestWebhook.IsEnabled = true;
                BtnTestWebhook.Content   = "TEST DISCORD WEBHOOK";
            }
        }

        // ─── Clock ────────────────────────────────────────────────────────────────

        private void SetupClock()
        {
            ClockText.Text  = DateTime.UtcNow.ToString("'UTC' HH:mm:ss");
            _clock.Interval = TimeSpan.FromSeconds(1);
            _clock.Tick    += (_, _) => ClockText.Text = DateTime.UtcNow.ToString("'UTC' HH:mm:ss");
            _clock.Start();
        }

        // ─── Charts ───────────────────────────────────────────────────────────────

        private void DrawCharts()
        {
            DrawSparkline(SparkQps,      "#4F8CFF", _epsHistory);
            DrawSparkline(SparkInjected, "#F59E0B", _injHistory);
            DrawSparkline(SparkFatal,    "#E5484D", _fatHistory);
            DrawSparkline(SparkAvgDur,   "#8B5CF6", _durHistory);
            DrawLatencyHistogram();
            DrawLevelDistribution();
            DrawTopDatabases();
        }

        private static void DrawSparkline(Canvas canvas, string hex, System.Collections.Generic.IEnumerable<double> dataSource)
        {
            const double w = 300, h = 60;
            canvas.Children.Clear();
            double[] pts = dataSource.ToArray();
            if (pts.Length < 2)
                pts = new double[] { 0, 0 };

            double min = pts.Min(), max = pts.Max();
            double range = max > min ? max - min : 1;
            var (_, lineBrush, fillBrush, _, _) = GetBrush(hex);
            var points = new PointCollection(pts.Length);
            for (int i = 0; i < pts.Length; i++)
            {
                double x = i * w / (pts.Length - 1);
                double y = h - 4 - (pts[i] - min) / range * (h - 8);
                points.Add(new Point(x, Math.Max(2, Math.Min(h - 2, y))));
            }
            var areaPts = new PointCollection(pts.Length + 2);
            foreach (var pt in points) areaPts.Add(pt);
            areaPts.Add(new Point(w, h));
            areaPts.Add(new Point(0, h));
            canvas.Children.Add(new Polygon
            {
                Points = areaPts,
                Fill   = fillBrush
            });
            canvas.Children.Add(new Polyline
            {
                Points          = points,
                Stroke          = lineBrush,
                StrokeThickness = 1.4
            });
        }

        private void DrawLatencyHistogram(double[]? sortedDurations = null)
        {
            const double w = 600, h = 120;
            const int    bins = 28;
            LatencyCanvas.Children.Clear();

            // Reuse pre-sorted snapshot from RefreshKpis when available
            double[] durations = sortedDurations
                ?? _entries.Select(e => e.Duration).Where(d => d > 0).ToArray();
            if (sortedDurations == null && durations.Length >= 5)
                Array.Sort(durations);
            double[] binValues;
            double   p95x;

            if (durations.Length >= 5)
            {
                const double logMin = -1, logMax = 5;
                double binW = (logMax - logMin) / bins;
                var counts = new double[bins];
                foreach (var d in durations)
                {
                    int b = (int)((Math.Log10(Math.Max(0.1, d)) - logMin) / binW);
                    if (b >= 0 && b < bins) counts[b]++;
                }
                binValues = counts;

                double p95    = durations[(int)(durations.Length * 0.95)];
                double p95log = Math.Log10(Math.Max(0.1, p95));
                p95x = w * Math.Clamp((p95log - logMin) / (logMax - logMin), 0.01, 0.99);
            }
            else
            {
                binValues = new double[bins];
                for (int i = 0; i < bins; i++)
                {
                    double x = (double)i / bins;
                    binValues[i] = Math.Exp(-Math.Pow((x - 0.2) * 4, 2))
                                 + Math.Exp(-Math.Pow((x - 0.7) * 6, 2)) * 0.25;
                }
                p95x = w * 0.76;
            }

            double bw       = w / bins;
            double maxCount = binValues.Max() > 0 ? binValues.Max() : 1;

            var histRed  = GetBrush("#E5484D").Fill178;
            var histAmb  = GetBrush("#F59E0B").Fill178;
            var histBlue = GetBrush("#4F8CFF").Fill178;
            var p95Brush = GetBrush("#F59E0B").Solid;

            for (int i = 0; i < bins; i++)
            {
                double bh = binValues[i] / maxCount * (h - 20);
                if (bh < 1) continue;
                var fill = i > 20 ? histRed : i > 14 ? histAmb : histBlue;
                var rect = new Rectangle
                {
                    Width  = Math.Max(1, bw - 2),
                    Height = bh,
                    Fill   = fill
                };
                Canvas.SetLeft(rect, i * bw + 1);
                Canvas.SetTop(rect, h - bh);
                LatencyCanvas.Children.Add(rect);
            }

            var marker = new Line
            {
                X1 = p95x, Y1 = 0, X2 = p95x, Y2 = h,
                Stroke          = p95Brush,
                StrokeDashArray = new DoubleCollection { 3, 3 },
                StrokeThickness = 1
            };
            LatencyCanvas.Children.Add(marker);
            var lbl = new TextBlock
            {
                Text       = "p95",
                Foreground  = p95Brush,
                FontFamily  = new FontFamily("Consolas"),
                FontSize    = 10
            };
            Canvas.SetLeft(lbl, p95x + 4);
            Canvas.SetTop(lbl, 4);
            LatencyCanvas.Children.Add(lbl);
        }

        private void DrawLevelDistribution()
        {
            LevelDistCanvas.Children.Clear();
            var buckets = new[] { "LOG",      "NOTICE",   "WARNING",  "ERROR",    "CRITICAL" };
            var hexes   = new[] { "#10B981",  "#8B5CF6",  "#F59E0B",  "#E5484D",  "#E5484D"  };

            var counts = _levelCounts;
            foreach (var b in buckets) counts[b] = 0;
            foreach (var e in _entries)
            {
                var bucket = e.Level.ToUpperInvariant() switch
                {
                    "CRITICAL" or "FATAL"   => "CRITICAL",
                    "HIGH"     or "ERROR"   => "ERROR",
                    "MEDIUM"   or "WARNING" => "WARNING",
                    "NOTICE"   or "LOW"     => "NOTICE",
                    _                       => "LOG"
                };
                counts[bucket]++;
            }

            double canvasW = LevelDistCanvas.ActualWidth > 10 ? LevelDistCanvas.ActualWidth : 400;
            const double barMaxH = 90;
            int    maxCount = counts.Values.Max() > 0 ? counts.Values.Max() : 1;
            double barW     = Math.Floor(canvasW / buckets.Length) - 8;
            double gap      = (canvasW - barW * buckets.Length) / (buckets.Length + 1);

            for (int i = 0; i < buckets.Length; i++)
            {
                string label = buckets[i];
                string hex   = hexes[i];
                int    count = counts[label];
                double bh    = count > 0 ? Math.Max(3, (double)count / maxCount * barMaxH) : 0;
                var (_, strokeBrush, _, fillBrush, _) = GetBrush(hex);
                double x = gap + i * (barW + gap);

                if (bh > 0)
                {
                    var rect = new Rectangle
                    {
                        Width           = barW,
                        Height          = bh,
                        Fill            = fillBrush,
                        Stroke          = strokeBrush,
                        StrokeThickness = 1
                    };
                    Canvas.SetLeft(rect, x);
                    Canvas.SetTop(rect, barMaxH - bh);
                    LevelDistCanvas.Children.Add(rect);
                }

                var tb = new TextBlock
                {
                    Text          = $"{label}\n{count:N0}",
                    Foreground    = (Brush)FindResource("TextMuteBrush"),
                    FontFamily    = new FontFamily("Consolas"),
                    FontSize      = 9,
                    TextAlignment = TextAlignment.Center,
                    Width         = barW
                };
                Canvas.SetLeft(tb, x);
                Canvas.SetTop(tb, barMaxH + 4);
                LevelDistCanvas.Children.Add(tb);
            }
        }

        private void DrawTopDatabases()
        {
            TopDbCanvas.Children.Clear();

            if (_entries.Count == 0)
            {
                var empty = new TextBlock
                {
                    Text       = "No data — start monitoring",
                    Foreground = (Brush)FindResource("TextMuteBrush"),
                    FontFamily = new FontFamily("Consolas"),
                    FontSize   = 11
                };
                Canvas.SetLeft(empty, 0);
                Canvas.SetTop(empty, 20);
                TopDbCanvas.Children.Add(empty);
                return;
            }

            var top5 = _entries
                .GroupBy(e => string.IsNullOrEmpty(e.Database) ? "(unknown)" : e.Database)
                .Select(g => (Key: g.Key, Count: g.Count()))
                .OrderByDescending(g => g.Count)
                .Take(5)
                .ToArray();

            double canvasW  = TopDbCanvas.ActualWidth > 10 ? TopDbCanvas.ActualWidth : 360;
            const double nameW = 130, countW = 50, rowH = 28;
            double barAreaW = Math.Max(20, canvasW - nameW - countW - 8);
            int    maxCount   = top5[0].Count;
            var    accentBrush = GetBrush("#4F8CFF").Solid;

            for (int i = 0; i < top5.Length; i++)
            {
                var    grp  = top5[i];
                double y    = i * rowH;
                double barW = (double)grp.Count / maxCount * barAreaW;

                var nameBlock = new TextBlock
                {
                    Text       = grp.Key.Length > 16 ? grp.Key[..16] + "…" : grp.Key,
                    Foreground = (Brush)FindResource("TextBrush"),
                    FontFamily = new FontFamily("Consolas"),
                    FontSize   = 11,
                    Width      = nameW
                };
                Canvas.SetLeft(nameBlock, 0);
                Canvas.SetTop(nameBlock, y + 2);
                TopDbCanvas.Children.Add(nameBlock);

                var track = new Rectangle
                {
                    Width  = barAreaW,
                    Height = 6,
                    Fill   = (Brush)FindResource("Bg3")
                };
                Canvas.SetLeft(track, nameW);
                Canvas.SetTop(track, y + 10);
                TopDbCanvas.Children.Add(track);

                var bar = new Rectangle
                {
                    Width  = Math.Max(2, barW),
                    Height = 6,
                    Fill   = accentBrush
                };
                Canvas.SetLeft(bar, nameW);
                Canvas.SetTop(bar, y + 10);
                TopDbCanvas.Children.Add(bar);

                var countBlock = new TextBlock
                {
                    Text       = $"{grp.Count:N0}",
                    Foreground = (Brush)FindResource("TextMuteBrush"),
                    FontFamily = new FontFamily("Consolas"),
                    FontSize   = 11
                };
                Canvas.SetLeft(countBlock, nameW + barAreaW + 8);
                Canvas.SetTop(countBlock, y + 2);
                TopDbCanvas.Children.Add(countBlock);
            }
        }

        // ─── Tab navigation ───────────────────────────────────────────────────────

        private void SwitchTab(string tab)
        {
            TabMonitor.Visibility   = tab == "monitor"   ? Visibility.Visible : Visibility.Collapsed;
            TabDashboard.Visibility = tab == "dashboard" ? Visibility.Visible : Visibility.Collapsed;
            TabModules.Visibility   = tab == "modules"   ? Visibility.Visible : Visibility.Collapsed;
            TabSettings.Visibility  = tab == "settings"  ? Visibility.Visible : Visibility.Collapsed;

            NavDashboard.Style = (Style)FindResource(tab == "dashboard" ? "NavBtnActive" : "NavBtn");
            NavMonitor.Style   = (Style)FindResource(tab == "monitor"   ? "NavBtnActive" : "NavBtn");
            NavModules.Style   = (Style)FindResource(tab == "modules"   ? "NavBtnActive" : "NavBtn");
            NavSettings.Style  = (Style)FindResource(tab == "settings"  ? "NavBtnActive" : "NavBtn");
        }

        private void NavDashboard_Click(object s, RoutedEventArgs e) => SwitchTab("dashboard");
        private void NavMonitor_Click(object s, RoutedEventArgs e)   => SwitchTab("monitor");
        private void NavSettings_Click(object s, RoutedEventArgs e)  => SwitchTab("settings");

        private bool _modulesLoaded;
        private void NavModules_Click(object s, RoutedEventArgs e)
        {
            SwitchTab("modules");
            if (!_modulesLoaded) LoadModulesTab();
        }

        // ─── Module Manager ───────────────────────────────────────────────────────

        private string NfaFolder => System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "NFA");

        private void BtnReloadAllModules_Click(object s, RoutedEventArgs e) => LoadModulesTab();

        private void BtnImportModule_Click(object s, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title       = "Import NFA Module",
                Filter      = "NFA Profile (*.json)|*.json",
                Multiselect = false
            };
            if (dlg.ShowDialog() != true) return;

            var dest = System.IO.Path.Combine(NfaFolder, System.IO.Path.GetFileName(dlg.FileName));
            try
            {
                System.IO.Directory.CreateDirectory(NfaFolder);
                System.IO.File.Copy(dlg.FileName, dest, overwrite: true);
                LoadModulesTab();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Import failed:\n{ex.Message}", "Import Module",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadModulesTab()
        {
            ModulesGrid.Children.Clear();
            var raws = NfaLoader.LoadAllRaw(NfaFolder);

            foreach (var (profile, filePath) in raws)
                ModulesGrid.Children.Add(BuildModuleCard(profile, filePath));

            var enabled = raws.Count(r => r.Profile.Enabled);
            ModulesSubtitle.Text = $"/ NFA automata  ·  {enabled}/{raws.Count} active";
            _modulesLoaded = true;
        }

        private Border BuildModuleCard(NFAModule.AutomatonProfile profile, string filePath)
        {
            // Threat colour
            var threatHex = profile.ThreatType switch
            {
                "SQLI"       => "#E5484D",
                "BRUTEFORCE" => "#F59E0B",
                "EXFIL"      => "#8B5CF6",
                _            => "#4F8CFF"
            };
            var tc = (Color)ColorConverter.ConvertFromString(threatHex);
            var threatBrush  = new SolidColorBrush(tc);
            var threatBgBrush  = new SolidColorBrush(Color.FromArgb(30,  tc.R, tc.G, tc.B));
            var threatBrdBrush = new SolidColorBrush(Color.FromArgb(80,  tc.R, tc.G, tc.B));

            // ── Threat badge
            var badge = new Border
            {
                CornerRadius    = new CornerRadius(4),
                Background      = threatBgBrush,
                BorderBrush     = threatBrdBrush,
                BorderThickness = new Thickness(1),
                Padding         = new Thickness(6, 2, 6, 2),
                VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text       = profile.ThreatType,
                    Foreground = threatBrush,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize   = 10
                }
            };

            // ── Name
            var nameBlock = new TextBlock
            {
                Text              = profile.Name,
                Foreground        = (Brush)FindResource("TextBrush"),
                FontFamily        = new FontFamily("Consolas"),
                FontSize          = 12,
                FontWeight        = FontWeights.Bold,
                Margin            = new Thickness(8, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming      = TextTrimming.CharacterEllipsis,
                MaxWidth          = 160
            };

            // ── Enabled toggle
            var toggle = new ToggleButton
            {
                Style     = (Style)FindResource("ToggleStyle"),
                IsChecked = profile.Enabled,
                Margin    = new Thickness(8, 0, 0, 0),
                Tag       = filePath,
                VerticalAlignment = VerticalAlignment.Center
            };
            toggle.Checked   += ModuleToggle_Checked;
            toggle.Unchecked += ModuleToggle_Unchecked;

            // ── Header grid: [badge + name] [spacer] [toggle]
            var headerGrid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            Grid.SetColumn(badge,     0);
            Grid.SetColumn(nameBlock, 1);
            Grid.SetColumn(toggle,    3);
            headerGrid.Children.Add(badge);
            headerGrid.Children.Add(nameBlock);
            headerGrid.Children.Add(toggle);

            // ── State diagram
            var diagram = BuildStatesDiagram(profile);

            // ── Stat chips
            var statsRow = new WrapPanel { Margin = new Thickness(0, 8, 0, 8), Orientation = Orientation.Horizontal };
            statsRow.Children.Add(MakeStat("STATES", profile.States.Count.ToString()));
            statsRow.Children.Add(MakeStat("TRANS",  profile.Transitions.Count.ToString()));
            statsRow.Children.Add(MakeStat("VER",    profile.Version));
            statsRow.Children.Add(MakeStat("SEV",    profile.Metadata.Severity));

            // ── Description
            var desc = new TextBlock
            {
                Text         = profile.Metadata.Description,
                Foreground   = (Brush)FindResource("TextMuteBrush"),
                FontFamily   = new FontFamily("Consolas"),
                FontSize     = 10,
                TextWrapping = TextWrapping.Wrap,
                Margin       = new Thickness(0, 0, 0, 10)
            };

            // ── Separator
            var sep = new Border
            {
                Height     = 1,
                Background = (Brush)FindResource("Line2Brush"),
                Margin     = new Thickness(0, 0, 0, 8)
            };

            // ── Footer: filename + reload button
            var fileLabel = new TextBlock
            {
                Text              = System.IO.Path.GetFileName(filePath),
                Foreground        = (Brush)FindResource("TextMuteBrush"),
                FontFamily        = new FontFamily("Consolas"),
                FontSize          = 9,
                TextTrimming      = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center
            };
            var reloadBtn = new Button
            {
                Content = "↺ Reload",
                Style   = (Style)FindResource("BtnGhost"),
                Padding = new Thickness(8, 2, 8, 2),
                Height  = 24,
                Tag     = filePath
            };
            reloadBtn.Click += ModuleReloadJson_Click;

            var footerGrid = new Grid();
            footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            Grid.SetColumn(fileLabel,  0);
            Grid.SetColumn(reloadBtn,  1);
            footerGrid.Children.Add(fileLabel);
            footerGrid.Children.Add(reloadBtn);

            // ── Card body
            var body = new StackPanel { Margin = new Thickness(14) };
            body.Children.Add(headerGrid);
            body.Children.Add(diagram);
            body.Children.Add(statsRow);
            body.Children.Add(desc);
            body.Children.Add(sep);
            body.Children.Add(footerGrid);

            return new Border
            {
                Width           = 320,
                Margin          = new Thickness(0, 0, 12, 12),
                CornerRadius    = new CornerRadius(10),
                Background      = (Brush)FindResource("Bg2"),
                BorderBrush     = (Brush)FindResource("Line2Brush"),
                BorderThickness = new Thickness(1),
                Tag             = filePath,
                Child           = body
            };
        }

        private StackPanel BuildStatesDiagram(NFAModule.AutomatonProfile profile)
        {
            var panel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin      = new Thickness(0, 0, 0, 0)
            };

            for (int i = 0; i < profile.States.Count; i++)
            {
                var st  = profile.States[i];
                var hex = st.IsAccept ? "#E5484D"
                        : st.IsStart  ? "#10B981"
                        :               "#64748B";
                var c      = (Color)ColorConverter.ConvertFromString(hex);
                var stroke = new SolidColorBrush(c);
                var fill   = new SolidColorBrush(Color.FromArgb(30, c.R, c.G, c.B));

                var lbl = st.Id.Length > 5 ? st.Id[^5..] : st.Id;

                var cell = new StackPanel { Margin = new Thickness(0, 0, 0, 0) };
                cell.Children.Add(new Ellipse
                {
                    Width           = 28,
                    Height          = 28,
                    Fill            = fill,
                    Stroke          = stroke,
                    StrokeThickness = 1.5
                });
                cell.Children.Add(new TextBlock
                {
                    Text                = lbl,
                    Foreground          = stroke,
                    FontFamily          = new FontFamily("Consolas"),
                    FontSize            = 8,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    TextTrimming        = TextTrimming.CharacterEllipsis
                });
                panel.Children.Add(cell);

                if (i < profile.States.Count - 1)
                    panel.Children.Add(new TextBlock
                    {
                        Text              = "→",
                        Foreground        = (Brush)FindResource("TextMuteBrush"),
                        FontSize          = 14,
                        VerticalAlignment = VerticalAlignment.Center,
                        Margin            = new Thickness(4, 0, 4, 14)
                    });
            }

            return panel;
        }

        private Border MakeStat(string label, string value)
        {
            var inner = new StackPanel { Margin = new Thickness(8, 4, 8, 4) };
            inner.Children.Add(new TextBlock
            {
                Text       = label,
                Foreground = (Brush)FindResource("TextMuteBrush"),
                FontFamily = new FontFamily("Consolas"),
                FontSize   = 8
            });
            inner.Children.Add(new TextBlock
            {
                Text       = value,
                Foreground = (Brush)FindResource("TextBrush"),
                FontFamily = new FontFamily("Consolas"),
                FontSize   = 11,
                FontWeight = FontWeights.Bold
            });
            return new Border
            {
                CornerRadius    = new CornerRadius(4),
                BorderBrush     = (Brush)FindResource("Line2Brush"),
                BorderThickness = new Thickness(1),
                Margin          = new Thickness(0, 0, 6, 0),
                Child           = inner
            };
        }

        private void ModuleToggle_Checked(object s, RoutedEventArgs e)   => SetModuleEnabled((FrameworkElement)s, true);
        private void ModuleToggle_Unchecked(object s, RoutedEventArgs e) => SetModuleEnabled((FrameworkElement)s, false);

        private void SetModuleEnabled(FrameworkElement element, bool enabled)
        {
            var filePath = (string)element.Tag;
            try
            {
                var node = JsonNode.Parse(System.IO.File.ReadAllText(filePath));
                if (node is JsonObject obj)
                {
                    if (obj.ContainsKey("enabled"))       obj["enabled"]  = enabled;
                    else if (obj.ContainsKey("Enabled"))  obj["Enabled"]  = enabled;
                    else obj["enabled"] = enabled;

                    var tmp = filePath + ".tmp";
                    System.IO.File.WriteAllText(tmp,
                        obj.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                    System.IO.File.Replace(tmp, filePath, null);
                }

                _liveWatcher?.ReloadEngines();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not update module:\n{ex.Message}", "Module Manager",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void ModuleReloadJson_Click(object s, RoutedEventArgs e)
        {
            var filePath = (string)((Button)s).Tag;

            // Find old card
            Border? oldCard = null;
            foreach (var child in ModulesGrid.Children.OfType<Border>())
            {
                if ((string?)child.Tag == filePath) { oldCard = child; break; }
            }

            try
            {
                var json    = System.IO.File.ReadAllText(filePath);
                var opts    = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var profile = JsonSerializer.Deserialize<NFAModule.AutomatonProfile>(json, opts);
                if (profile is null) return;

                var newCard = BuildModuleCard(profile, filePath);
                if (oldCard != null)
                {
                    int idx = ModulesGrid.Children.IndexOf(oldCard);
                    ModulesGrid.Children.RemoveAt(idx);
                    ModulesGrid.Children.Insert(idx, newCard);
                }
                else
                {
                    ModulesGrid.Children.Add(newCard);
                }

                _liveWatcher?.ReloadEngines();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Reload failed:\n{ex.Message}", "Module Manager",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ─── Search & Filter ──────────────────────────────────────────────────────

        private bool FilterEntry(object obj)
        {
            if (obj is not LogEntry entry) return false;

            var bucket = entry.Level.ToUpperInvariant() switch
            {
                "CRITICAL"                     => "CRITICAL",
                "HIGH"                         => "HIGH",
                "MEDIUM"                       => "MEDIUM",
                "LOW"                          => "LOW",
                "FATAL" or "ERROR" or "WARNING" => "WARNING",
                _                              => "LOG"
            };
            if (!_activeFilters.Contains(bucket)) return false;

            if (!string.IsNullOrEmpty(_searchText))
            {
                return entry.Query.Contains(_searchText, StringComparison.OrdinalIgnoreCase)      ||
                       entry.UserHost.Contains(_searchText, StringComparison.OrdinalIgnoreCase)   ||
                       entry.Database.Contains(_searchText, StringComparison.OrdinalIgnoreCase)   ||
                       entry.ThreatType.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
                       entry.Timestamp.Contains(_searchText, StringComparison.OrdinalIgnoreCase);
            }

            return true;
        }

        private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            _searchText = ((TextBox)sender).Text.Trim();
            _view?.Refresh();
        }

        private void FilterChip_Changed(object sender, RoutedEventArgs e)
        {
            var chip = (ToggleButton)sender;
            var tag  = (string)chip.Tag;
            if (chip.IsChecked == true) _activeFilters.Add(tag);
            else _activeFilters.Remove(tag);
            _view?.Refresh();
        }

        // ─── Window chrome ────────────────────────────────────────────────────────

        private void TitleBar_MouseDown(object s, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
                WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            else if (e.ChangedButton == MouseButton.Left)
                DragMove();
        }

        private void BtnMinimize_Click(object s, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void BtnMaximize_Click(object s, RoutedEventArgs e) =>
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        private void BtnClose_Click(object s, RoutedEventArgs e) => Close();

        // ─── Mock data (initial state) ────────────────────────────────────────────

        private void LoadData()
        {
            var data = new[]
            {
                new LogEntry { Timestamp="2026-04-19 14:26:08.214 UTC", Pid=48214, Level="HIGH",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM users WHERE email='a' OR 1=1--",              Duration=12.4,    IsInjected=true,  ThreatType="SQLI"       },
                new LogEntry { Timestamp="2026-04-19 14:26:08.092 UTC", Pid=48102, Level="LOG",      UserHost="analyst_02@10.2.4.18", Database="crm_readonly", Query="SELECT name,email FROM customers LIMIT 50",                 Duration=8.1,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.980 UTC", Pid=48214, Level="LOG",      UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="UPDATE orders SET status='shipped' WHERE id=4812",          Duration=4.2,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.814 UTC", Pid=48317, Level="WARNING",  UserHost="migrator@10.2.7.1",    Database="billing_prod", Query="ALTER TABLE invoices ADD COLUMN tax_region VARCHAR(8)",      Duration=612.0,   IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.612 UTC", Pid=48402, Level="HIGH",     UserHost="unknown@10.0.4.22",    Database="auth_prod",    Query="SELECT password_hash FROM admins",                          Duration=22.9,    IsInjected=true,  ThreatType="EXFIL"      },
                new LogEntry { Timestamp="2026-04-19 14:26:07.441 UTC", Pid=48218, Level="LOG",      UserHost="svc_worker@10.2.4.12", Database="events_hot",   Query="INSERT INTO events VALUES (…) ×240",                       Duration=18.7,    IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.220 UTC", Pid=48102, Level="LOG",      UserHost="analyst_02@10.2.4.18", Database="crm_readonly", Query="SELECT COUNT(*) FROM customers WHERE region='EMEA'",        Duration=112.3,   IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.998 UTC", Pid=48214, Level="LOG",      UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM sessions WHERE token='eyJhbGciOi…'",          Duration=2.1,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.812 UTC", Pid=48214, Level="HIGH",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM users; DROP TABLE users;--",                  Duration=0.8,     IsInjected=true,  ThreatType="SQLI"       },
                new LogEntry { Timestamp="2026-04-19 14:26:06.644 UTC", Pid=48501, Level="NOTICE",   UserHost="ops_cli@10.0.0.4",     Database="billing_prod", Query="VACUUM ANALYZE invoices",                                   Duration=1842.0,  IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.412 UTC", Pid=48214, Level="WARNING",  UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT id,email FROM users LIMIT 100000",                  Duration=982.0,   IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.201 UTC", Pid=48218, Level="LOG",      UserHost="svc_worker@10.2.4.12", Database="events_hot",   Query="DELETE FROM events WHERE ts < NOW() - INTERVAL '7 days'",  Duration=410.0,   IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.998 UTC", Pid=48622, Level="WARNING",  UserHost="login@10.0.9.1",       Database="auth_prod",    Query="SELECT id FROM users WHERE pwd='…' attempt 14",            Duration=6.4,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.772 UTC", Pid=48102, Level="LOG",      UserHost="analyst_02@10.2.4.18", Database="crm_readonly", Query="SELECT * FROM orders WHERE total > 10000",                 Duration=74.2,    IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.510 UTC", Pid=48214, Level="LOG",      UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT product_id FROM cart_items WHERE cart_id=1402",     Duration=1.6,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.240 UTC", Pid=48214, Level="HIGH",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM users UNION SELECT load_file('/etc/passwd')", Duration=3.2,     IsInjected=true,  ThreatType="SQLI"       },
                new LogEntry { Timestamp="2026-04-19 14:26:05.012 UTC", Pid=48700, Level="WARNING",  UserHost="etl_nightly@10.3.1.4", Database="warehouse",    Query="COPY fact_sales TO 's3://bucket/export'",                  Duration=48210.0, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.880 UTC", Pid=48214, Level="LOG",      UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM orders WHERE id=4012",                       Duration=1.4,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.712 UTC", Pid=48501, Level="NOTICE",   UserHost="ops_cli@10.0.0.4",     Database="auth_prod",    Query="GRANT SELECT ON users TO readonly_role",                   Duration=11.2,    IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.502 UTC", Pid=48214, Level="LOG",      UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM orders WHERE id=4011",                       Duration=1.3,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.281 UTC", Pid=48622, Level="WARNING",  UserHost="login@10.0.9.1",       Database="auth_prod",    Query="SELECT id FROM users WHERE pwd='…' attempt 15",            Duration=5.8,     IsInjected=false },
            };
            foreach (var e in data) _entries.Add(e);
        }
    }
}
