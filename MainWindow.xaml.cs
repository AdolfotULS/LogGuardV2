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

    public class LogEntry
    {
        public string Timestamp  { get; set; } = "";
        public int    Pid        { get; set; }
        public string Level      { get; set; } = "";
        public string UserHost   { get; set; } = "";
        public string Database   { get; set; } = "";
        public string Query      { get; set; } = "";
        public double Duration   { get; set; }
        public bool   IsInjected { get; set; }
    }

    public class LevelToSevColorConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "FATAL" or "ERROR" => Application.Current.Resources["DangerBrush"],
            "WARNING"          => Application.Current.Resources["WarnBrush"],
            "NOTICE"           => Application.Current.Resources["InfoBrush"],
            _                  => Application.Current.Resources["OkBrush"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class LevelToBadgeFgConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "FATAL"   => Brushes.White,
            "ERROR"   => Application.Current.Resources["DangerBrush"],
            "WARNING" => Application.Current.Resources["WarnBrush"],
            "NOTICE"  => Application.Current.Resources["InfoBrush"],
            _         => Application.Current.Resources["TextMuteBrush"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class LevelToBadgeBgConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "FATAL"   => Application.Current.Resources["DangerBrush"],
            "ERROR"   => new SolidColorBrush(Color.FromArgb(20,  229, 72,  77)),
            "WARNING" => new SolidColorBrush(Color.FromArgb(20,  245, 158, 11)),
            "NOTICE"  => new SolidColorBrush(Color.FromArgb(20,  139, 92,  246)),
            _         => Application.Current.Resources["Bg2"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class LevelToBadgeBorderConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "FATAL"   => Application.Current.Resources["DangerBrush"],
            "ERROR"   => new SolidColorBrush(Color.FromArgb(100, 229, 72,  77)),
            "WARNING" => new SolidColorBrush(Color.FromArgb(100, 245, 158, 11)),
            "NOTICE"  => new SolidColorBrush(Color.FromArgb(100, 139, 92,  246)),
            _         => Application.Current.Resources["Line2Brush"]
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
        public object Convert(object v, Type t, object p, CultureInfo c) =>
            (bool)v ? (object)new SolidColorBrush(Color.FromArgb(20,  229, 72, 77))
                    : Application.Current.Resources["Bg2"];
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class BoolToInjBorderConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) =>
            (bool)v ? (object)new SolidColorBrush(Color.FromArgb(100, 229, 72, 77))
                    : Application.Current.Resources["Line2Brush"];
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
        private readonly DispatcherTimer _clock   = new();
        private readonly DispatcherTimer _kpiTimer = new();
        private LogLiveWatcher? _liveWatcher;
        private bool _isWatching;
        private readonly DateTime _appStart = DateTime.UtcNow;

        // Counters — written on thread-pool, read on UI thread via Interlocked
        private long _totalEvents;
        private long _fatalErrorCount;
        private long _injectedCount;
        private long _durationSumMs;   // integer ms for atomicity

        public MainWindow()
        {
            InitializeComponent();
            LoadData();
            LoadSettingsToForm();
            SetupClock();
            SetupKpiTimer();
            LogGrid.ItemsSource = _entries;
            Loaded += (_, _) => DrawCharts();
            Closed += (_, _) => StopWatcher();
        }

        // ─── Watcher lifecycle ────────────────────────────────────────────────────

        private void BtnStart_Click(object s, RoutedEventArgs e) => StartWatcher();
        private void BtnStop_Click(object s, RoutedEventArgs e)  => StopWatcher();

        private void StartWatcher()
        {
            if (_isWatching) return;

            var settings  = ReadSettingsFromForm();
            var nfaFolder = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "NFA");

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

        private void OnLiveEntry(LogEntry entry)
        {
            Interlocked.Increment(ref _totalEvents);
            if (entry.Level is "FATAL" or "ERROR") Interlocked.Increment(ref _fatalErrorCount);
            if (entry.IsInjected)                  Interlocked.Increment(ref _injectedCount);
            Interlocked.Add(ref _durationSumMs, (long)entry.Duration);

            Dispatcher.InvokeAsync(() => _entries.Insert(0, entry));
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
            var total    = Interlocked.Read(ref _totalEvents);
            var errors   = Interlocked.Read(ref _fatalErrorCount);
            var injected = Interlocked.Read(ref _injectedCount);
            var durSum   = Interlocked.Read(ref _durationSumMs);
            var avg      = total > 0 ? (double)durSum / total : 0.0;
            var uptime   = DateTime.UtcNow - _appStart;

            KpiEventsPerSec.Text = total.ToString("N0");
            KpiFatalError.Text   = errors.ToString("N0");
            KpiInjected.Text     = injected.ToString("N0");
            KpiAvgDuration.Text  = avg.ToString("F1");
            KpiUptime.Text       = uptime.ToString(@"hh\:mm\:ss");

            if (_isWatching && _liveWatcher != null)
                StatusText.Text =
                    $"LIVE · events: {total:N0} │ injected: {injected:N0} │ modules: {_liveWatcher.EngineCount}";
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
            TxtWebhookUrl.Text           = s.AlertWebhookUrl;
            TxtMinLevel.Text             = s.AlertMinLevel;
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
            AlertMinLevel          = TxtMinLevel.Text.Trim()
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
            var rng = new Random(42);
            DrawSparkline(SparkQps, "#4F8CFF", rng, 14, 48);
            DrawSparkline(SparkMem, "#F59E0B", rng, 18, 38);
            DrawSparkline(SparkCpu, "#10B981", rng, 12, 42);
            DrawSparkline(SparkLag, "#8B5CF6", rng, 10, 30);
            DrawLatencyHistogram();
        }

        private static void DrawSparkline(Canvas canvas, string hex, Random rng, double lo, double hi)
        {
            const double w = 300, h = 60;
            const int    pts = 48;
            canvas.Children.Clear();
            var color  = (Color)ColorConverter.ConvertFromString(hex);
            var points = new PointCollection();
            for (int i = 0; i < pts; i++)
            {
                double x = i * w / (pts - 1);
                double y = h - Math.Max(2, Math.Min(h - 2,
                    lo + rng.NextDouble() * (hi - lo) + Math.Sin(i * 0.4) * 6));
                points.Add(new Point(x, y));
            }
            var areaPts = new PointCollection(points) { new(w, h), new(0, h) };
            canvas.Children.Add(new Polygon
            {
                Points = areaPts,
                Fill   = new SolidColorBrush(Color.FromArgb(36, color.R, color.G, color.B))
            });
            canvas.Children.Add(new Polyline
            {
                Points          = points,
                Stroke          = new SolidColorBrush(color),
                StrokeThickness = 1.4
            });
        }

        private void DrawLatencyHistogram()
        {
            const double w = 600, h = 120;
            const int    bins = 28;
            LatencyCanvas.Children.Clear();
            double bw = w / bins;
            for (int i = 0; i < bins; i++)
            {
                double x  = (double)i / bins;
                double v  = Math.Exp(-Math.Pow((x - 0.2) * 4, 2))
                          + Math.Exp(-Math.Pow((x - 0.7) * 6, 2)) * 0.25;
                double bh = v * (h - 20);
                string hx = i > 20 ? "#E5484D" : i > 14 ? "#F59E0B" : "#4F8CFF";
                var    c  = (Color)ColorConverter.ConvertFromString(hx);
                var rect  = new Rectangle
                {
                    Width  = Math.Max(1, bw - 2),
                    Height = bh,
                    Fill   = new SolidColorBrush(Color.FromArgb(178, c.R, c.G, c.B))
                };
                Canvas.SetLeft(rect, i * bw + 1);
                Canvas.SetTop(rect, h - bh);
                LatencyCanvas.Children.Add(rect);
            }
            var marker = new Line
            {
                X1 = w * 0.76, Y1 = 0, X2 = w * 0.76, Y2 = h,
                Stroke          = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B")),
                StrokeDashArray = new DoubleCollection { 3, 3 },
                StrokeThickness = 1
            };
            LatencyCanvas.Children.Add(marker);
            var lbl = new TextBlock
            {
                Text        = "p95",
                Foreground  = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B")),
                FontFamily  = new FontFamily("Consolas"),
                FontSize    = 10
            };
            Canvas.SetLeft(lbl, w * 0.76 + 4);
            Canvas.SetTop(lbl, 4);
            LatencyCanvas.Children.Add(lbl);
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

        private static void SetModuleEnabled(FrameworkElement element, bool enabled)
        {
            var filePath = (string)element.Tag;
            try
            {
                var node = JsonNode.Parse(System.IO.File.ReadAllText(filePath));
                if (node is JsonObject obj)
                {
                    // Handle both "enabled" and "Enabled" keys
                    if (obj.ContainsKey("enabled"))  obj["enabled"]  = enabled;
                    else if (obj.ContainsKey("Enabled")) obj["Enabled"] = enabled;
                    else obj["enabled"] = enabled;

                    System.IO.File.WriteAllText(filePath,
                        obj.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                }
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
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Reload failed:\n{ex.Message}", "Module Manager",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
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
                new LogEntry { Timestamp="2026-04-19 14:26:08.214 UTC", Pid=48214, Level="ERROR",   UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM users WHERE email='a' OR 1=1--",              Duration=12.4,    IsInjected=true  },
                new LogEntry { Timestamp="2026-04-19 14:26:08.092 UTC", Pid=48102, Level="LOG",     UserHost="analyst_02@10.2.4.18", Database="crm_readonly", Query="SELECT name,email FROM customers LIMIT 50",                 Duration=8.1,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.980 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="UPDATE orders SET status='shipped' WHERE id=4812",          Duration=4.2,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.814 UTC", Pid=48317, Level="WARNING", UserHost="migrator@10.2.7.1",    Database="billing_prod", Query="ALTER TABLE invoices ADD COLUMN tax_region VARCHAR(8)",      Duration=612.0,   IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.612 UTC", Pid=48402, Level="FATAL",   UserHost="unknown@10.0.4.22",    Database="auth_prod",    Query="SELECT password_hash FROM admins",                          Duration=22.9,    IsInjected=true  },
                new LogEntry { Timestamp="2026-04-19 14:26:07.441 UTC", Pid=48218, Level="LOG",     UserHost="svc_worker@10.2.4.12", Database="events_hot",   Query="INSERT INTO events VALUES (…) ×240",                       Duration=18.7,    IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.220 UTC", Pid=48102, Level="LOG",     UserHost="analyst_02@10.2.4.18", Database="crm_readonly", Query="SELECT COUNT(*) FROM customers WHERE region='EMEA'",        Duration=112.3,   IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.998 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM sessions WHERE token='eyJhbGciOi…'",          Duration=2.1,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.812 UTC", Pid=48214, Level="ERROR",   UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM users; DROP TABLE users;--",                 Duration=0.8,     IsInjected=true  },
                new LogEntry { Timestamp="2026-04-19 14:26:06.644 UTC", Pid=48501, Level="NOTICE",  UserHost="ops_cli@10.0.0.4",     Database="billing_prod", Query="VACUUM ANALYZE invoices",                                   Duration=1842.0,  IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.412 UTC", Pid=48214, Level="WARNING", UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT id,email FROM users LIMIT 100000",                  Duration=982.0,   IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.201 UTC", Pid=48218, Level="LOG",     UserHost="svc_worker@10.2.4.12", Database="events_hot",   Query="DELETE FROM events WHERE ts < NOW() - INTERVAL '7 days'",  Duration=410.0,   IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.998 UTC", Pid=48622, Level="WARNING", UserHost="login@10.0.9.1",       Database="auth_prod",    Query="SELECT id FROM users WHERE pwd='…' attempt 14",            Duration=6.4,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.772 UTC", Pid=48102, Level="LOG",     UserHost="analyst_02@10.2.4.18", Database="crm_readonly", Query="SELECT * FROM orders WHERE total > 10000",                 Duration=74.2,    IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.510 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT product_id FROM cart_items WHERE cart_id=1402",     Duration=1.6,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.240 UTC", Pid=48214, Level="ERROR",   UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM users UNION SELECT load_file('/etc/passwd')", Duration=3.2,     IsInjected=true  },
                new LogEntry { Timestamp="2026-04-19 14:26:05.012 UTC", Pid=48700, Level="WARNING", UserHost="etl_nightly@10.3.1.4", Database="warehouse",    Query="COPY fact_sales TO 's3://bucket/export'",                  Duration=48210.0, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.880 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM orders WHERE id=4012",                       Duration=1.4,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.712 UTC", Pid=48501, Level="NOTICE",  UserHost="ops_cli@10.0.0.4",     Database="auth_prod",    Query="GRANT SELECT ON users TO readonly_role",                   Duration=11.2,    IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.502 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM orders WHERE id=4011",                       Duration=1.3,     IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.281 UTC", Pid=48622, Level="WARNING", UserHost="login@10.0.9.1",       Database="auth_prod",    Query="SELECT id FROM users WHERE pwd='…' attempt 15",            Duration=5.8,     IsInjected=false },
            };
            foreach (var e in data) _entries.Add(e);
            LogGrid.ItemsSource = _entries;
        }
    }
}
