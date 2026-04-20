using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using LogGuardV2.src.Engine;

namespace LogGuardV2
{
    public class LogEntry
    {
        public string Timestamp { get; set; } = "";
        public int Pid { get; set; }
        public string Level { get; set; } = "";
        public string UserHost { get; set; } = "";
        public string Database { get; set; } = "";
        public string Query { get; set; } = "";
        public double Duration { get; set; }
        public bool IsInjected { get; set; }
    }

    public class LevelToSevColorConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "FATAL" or "ERROR" => Application.Current.Resources["DangerBrush"],
            "WARNING" => Application.Current.Resources["WarnBrush"],
            "NOTICE" => Application.Current.Resources["InfoBrush"],
            _ => Application.Current.Resources["OkBrush"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class LevelToBadgeFgConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "FATAL" => Brushes.White,
            "ERROR" => Application.Current.Resources["DangerBrush"],
            "WARNING" => Application.Current.Resources["WarnBrush"],
            "NOTICE" => Application.Current.Resources["InfoBrush"],
            _ => Application.Current.Resources["TextMuteBrush"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class LevelToBadgeBgConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "FATAL" => Application.Current.Resources["DangerBrush"],
            "ERROR" => new SolidColorBrush(Color.FromArgb(20, 229, 72, 77)),
            "WARNING" => new SolidColorBrush(Color.FromArgb(20, 245, 158, 11)),
            "NOTICE" => new SolidColorBrush(Color.FromArgb(20, 139, 92, 246)),
            _ => Application.Current.Resources["Bg2"]
        };
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class LevelToBadgeBorderConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => (string)v switch
        {
            "FATAL" => Application.Current.Resources["DangerBrush"],
            "ERROR" => new SolidColorBrush(Color.FromArgb(100, 229, 72, 77)),
            "WARNING" => new SolidColorBrush(Color.FromArgb(100, 245, 158, 11)),
            "NOTICE" => new SolidColorBrush(Color.FromArgb(100, 139, 92, 246)),
            _ => Application.Current.Resources["Line2Brush"]
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
            (bool)v ? Application.Current.Resources["DangerBrush"] : Application.Current.Resources["TextMuteBrush"];
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class BoolToInjBgConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) =>
            (bool)v ? (object)new SolidColorBrush(Color.FromArgb(20, 229, 72, 77)) : Application.Current.Resources["Bg2"];
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class BoolToInjBorderConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) =>
            (bool)v ? (object)new SolidColorBrush(Color.FromArgb(100, 229, 72, 77)) : Application.Current.Resources["Line2Brush"];
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class DurFmtConverter : IValueConverter
    {
        public object Convert(object v, Type t, object p, CultureInfo c) => ((double)v).ToString("F1");
        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public partial class MainWindow : Window
    {
        private readonly ObservableCollection<LogEntry> _entries = new();
        private readonly DispatcherTimer _clock = new();
        private LogLiveWatcher? _liveWatcher;

        public MainWindow()
        {
            InitializeComponent();
            LoadData();
            SetupClock();
            Loaded += (_, _) =>
            {
                DrawCharts();
                StartLiveWatcher();
            };
            Closed += (_, _) => _liveWatcher?.Dispose();
        }

        private void StartLiveWatcher()
        {
            var settings  = SettingsService.Load();
            var nfaFolder = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "NFA");
            _liveWatcher  = new LogLiveWatcher(settings, nfaFolder);
            _liveWatcher.EntryDetected += entry =>
                Dispatcher.InvokeAsync(() => _entries.Insert(0, entry));
            _liveWatcher.Start(settings.ReplayOnStart);
        }

        private void LoadData()
        {
            var data = new[]
            {
                new LogEntry { Timestamp="2026-04-19 14:26:08.214 UTC", Pid=48214, Level="ERROR",   UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM users WHERE email='a' OR 1=1--", Duration=12.4, IsInjected=true },
                new LogEntry { Timestamp="2026-04-19 14:26:08.092 UTC", Pid=48102, Level="LOG",     UserHost="analyst_02@10.2.4.18", Database="crm_readonly", Query="SELECT name,email FROM customers LIMIT 50", Duration=8.1, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.980 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="UPDATE orders SET status='shipped' WHERE id=4812", Duration=4.2, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.814 UTC", Pid=48317, Level="WARNING", UserHost="migrator@10.2.7.1",    Database="billing_prod", Query="ALTER TABLE invoices ADD COLUMN tax_region VARCHAR(8)", Duration=612.0, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.612 UTC", Pid=48402, Level="FATAL",   UserHost="unknown@10.0.4.22",    Database="auth_prod",    Query="SELECT password_hash FROM admins", Duration=22.9, IsInjected=true },
                new LogEntry { Timestamp="2026-04-19 14:26:07.441 UTC", Pid=48218, Level="LOG",     UserHost="svc_worker@10.2.4.12", Database="events_hot",   Query="INSERT INTO events VALUES (…) ×240", Duration=18.7, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:07.220 UTC", Pid=48102, Level="LOG",     UserHost="analyst_02@10.2.4.18", Database="crm_readonly", Query="SELECT COUNT(*) FROM customers WHERE region='EMEA'", Duration=112.3, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.998 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM sessions WHERE token='eyJhbGciOi…'", Duration=2.1, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.812 UTC", Pid=48214, Level="ERROR",   UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM users; DROP TABLE users;--", Duration=0.8, IsInjected=true },
                new LogEntry { Timestamp="2026-04-19 14:26:06.644 UTC", Pid=48501, Level="NOTICE",  UserHost="ops_cli@10.0.0.4",     Database="billing_prod", Query="VACUUM ANALYZE invoices", Duration=1842.0, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.412 UTC", Pid=48214, Level="WARNING", UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT id,email FROM users LIMIT 100000", Duration=982.0, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:06.201 UTC", Pid=48218, Level="LOG",     UserHost="svc_worker@10.2.4.12", Database="events_hot",   Query="DELETE FROM events WHERE ts < NOW() - INTERVAL '7 days'", Duration=410.0, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.998 UTC", Pid=48622, Level="WARNING", UserHost="login@10.0.9.1",       Database="auth_prod",    Query="SELECT id FROM users WHERE pwd='…' attempt 14", Duration=6.4, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.772 UTC", Pid=48102, Level="LOG",     UserHost="analyst_02@10.2.4.18", Database="crm_readonly", Query="SELECT * FROM orders WHERE total > 10000", Duration=74.2, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.510 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT product_id FROM cart_items WHERE cart_id=1402", Duration=1.6, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:05.240 UTC", Pid=48214, Level="ERROR",   UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM users UNION SELECT load_file('/etc/passwd')", Duration=3.2, IsInjected=true },
                new LogEntry { Timestamp="2026-04-19 14:26:05.012 UTC", Pid=48700, Level="WARNING", UserHost="etl_nightly@10.3.1.4", Database="warehouse",    Query="COPY fact_sales TO 's3://bucket/export'", Duration=48210.0, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.880 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM orders WHERE id=4012", Duration=1.4, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.712 UTC", Pid=48501, Level="NOTICE",  UserHost="ops_cli@10.0.0.4",     Database="auth_prod",    Query="GRANT SELECT ON users TO readonly_role", Duration=11.2, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.502 UTC", Pid=48214, Level="LOG",     UserHost="svc_api@10.2.4.9",     Database="orders_prod",  Query="SELECT * FROM orders WHERE id=4011", Duration=1.3, IsInjected=false },
                new LogEntry { Timestamp="2026-04-19 14:26:04.281 UTC", Pid=48622, Level="WARNING", UserHost="login@10.0.9.1",       Database="auth_prod",    Query="SELECT id FROM users WHERE pwd='…' attempt 15", Duration=5.8, IsInjected=false },
            };
            foreach (var e in data) _entries.Add(e);
            LogGrid.ItemsSource = _entries;
        }

        private void SetupClock()
        {
            ClockText.Text = DateTime.UtcNow.ToString("'UTC' HH:mm:ss");
            _clock.Interval = TimeSpan.FromSeconds(1);
            _clock.Tick += (_, _) => ClockText.Text = DateTime.UtcNow.ToString("'UTC' HH:mm:ss");
            _clock.Start();
        }

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
            const int pts = 48;
            canvas.Children.Clear();
            var color = (Color)ColorConverter.ConvertFromString(hex);
            var points = new PointCollection();
            for (int i = 0; i < pts; i++)
            {
                double x = i * w / (pts - 1);
                double y = h - Math.Max(2, Math.Min(h - 2, lo + rng.NextDouble() * (hi - lo) + Math.Sin(i * 0.4) * 6));
                points.Add(new Point(x, y));
            }
            var areaPts = new PointCollection(points) { new(w, h), new(0, h) };
            canvas.Children.Add(new Polygon
            {
                Points = areaPts,
                Fill = new SolidColorBrush(Color.FromArgb(36, color.R, color.G, color.B))
            });
            canvas.Children.Add(new Polyline
            {
                Points = points,
                Stroke = new SolidColorBrush(color),
                StrokeThickness = 1.4
            });
        }

        private void DrawLatencyHistogram()
        {
            const double w = 600, h = 120;
            const int bins = 28;
            LatencyCanvas.Children.Clear();
            double bw = w / bins;
            for (int i = 0; i < bins; i++)
            {
                double x = (double)i / bins;
                double v = Math.Exp(-Math.Pow((x - 0.2) * 4, 2)) + Math.Exp(-Math.Pow((x - 0.7) * 6, 2)) * 0.25;
                double bh = v * (h - 20);
                string hex = i > 20 ? "#E5484D" : i > 14 ? "#F59E0B" : "#4F8CFF";
                var c = (Color)ColorConverter.ConvertFromString(hex);
                var rect = new Rectangle
                {
                    Width = Math.Max(1, bw - 2),
                    Height = bh,
                    Fill = new SolidColorBrush(Color.FromArgb(178, c.R, c.G, c.B))
                };
                Canvas.SetLeft(rect, i * bw + 1);
                Canvas.SetTop(rect, h - bh);
                LatencyCanvas.Children.Add(rect);
            }
            var marker = new Line
            {
                X1 = w * 0.76, Y1 = 0, X2 = w * 0.76, Y2 = h,
                Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B")),
                StrokeDashArray = new DoubleCollection { 3, 3 },
                StrokeThickness = 1
            };
            LatencyCanvas.Children.Add(marker);
            var lbl = new TextBlock
            {
                Text = "p95",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B")),
                FontFamily = new FontFamily("Consolas"),
                FontSize = 10
            };
            Canvas.SetLeft(lbl, w * 0.76 + 4);
            Canvas.SetTop(lbl, 4);
            LatencyCanvas.Children.Add(lbl);
        }

        private void SwitchTab(string tab)
        {
            TabMonitor.Visibility  = tab == "monitor"  ? Visibility.Visible : Visibility.Collapsed;
            TabDashboard.Visibility = tab == "dashboard" ? Visibility.Visible : Visibility.Collapsed;
            TabModules.Visibility  = tab == "modules"  ? Visibility.Visible : Visibility.Collapsed;
            TabSettings.Visibility = tab == "settings" ? Visibility.Visible : Visibility.Collapsed;

            NavDashboard.Style = (Style)FindResource(tab == "dashboard" ? "NavBtnActive" : "NavBtn");
            NavMonitor.Style   = (Style)FindResource(tab == "monitor"   ? "NavBtnActive" : "NavBtn");
            NavModules.Style   = (Style)FindResource(tab == "modules"   ? "NavBtnActive" : "NavBtn");
            NavSettings.Style  = (Style)FindResource(tab == "settings"  ? "NavBtnActive" : "NavBtn");
        }

        private void NavDashboard_Click(object s, RoutedEventArgs e) => SwitchTab("dashboard");
        private void NavMonitor_Click(object s, RoutedEventArgs e)   => SwitchTab("monitor");
        private void NavModules_Click(object s, RoutedEventArgs e)   => SwitchTab("modules");
        private void NavSettings_Click(object s, RoutedEventArgs e)  => SwitchTab("settings");

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

        private void BtnSaveSettings_Click(object s, RoutedEventArgs e) { }
        private void BtnDiscardSettings_Click(object s, RoutedEventArgs e) { }
        private void BtnBrowseLogDir_Click(object s, RoutedEventArgs e) { }
        private void BtnTestPattern_Click(object s, RoutedEventArgs e) { }
    }
}
