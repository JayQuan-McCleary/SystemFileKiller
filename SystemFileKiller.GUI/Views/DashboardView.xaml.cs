using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SystemFileKiller.Core;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;

namespace SystemFileKiller.GUI.Views;

public partial class DashboardView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;
    public event Action<string>? OnNavigate;

    private readonly ObservableCollection<ThreatRow> _threats = new();
    private readonly ObservableCollection<LogRow> _log = new();
    private DateTime? _lastSweep;

    public DashboardView()
    {
        InitializeComponent();
        ThreatsList.ItemsSource = _threats;
        LogList.ItemsSource = _log;

        Loaded += (_, _) =>
        {
            // Replay existing operator log on load
            foreach (var e in OperatorLog.Snapshot()) AddLogRow(e);
            OperatorLog.Appended += OnOperatorLog;
            UpdateStats();
        };
        Unloaded += (_, _) => OperatorLog.Appended -= OnOperatorLog;
    }

    public sealed class ThreatRow
    {
        public string Subject { get; init; } = "";
        public string Surface { get; init; } = "";
        public string Verdict { get; init; } = "";
    }

    public sealed class LogRow
    {
        public DateTime Timestamp { get; init; }
        public OperatorLog.Kind Kind { get; init; }
        public string Text { get; init; } = "";
        public string TimestampDisplay => $"[{Timestamp:HH:mm:ss}]";
        public string KindDisplay => Kind switch
        {
            OperatorLog.Kind.Ok => "OK  ",
            OperatorLog.Kind.Warn => "WARN",
            OperatorLog.Kind.Err => "ERR ",
            _ => "INFO"
        };
        public Brush KindBrush => Kind switch
        {
            OperatorLog.Kind.Ok => (Brush)Application.Current.Resources["Green"],
            OperatorLog.Kind.Warn => (Brush)Application.Current.Resources["Amber"],
            OperatorLog.Kind.Err => (Brush)Application.Current.Resources["Accent2"],
            _ => (Brush)Application.Current.Resources["Blue"],
        };
    }

    private void OnOperatorLog(OperatorLog.Entry e)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => OnOperatorLog(e)); return; }
        AddLogRow(e);
    }

    private void AddLogRow(OperatorLog.Entry e)
    {
        _log.Add(new LogRow { Timestamp = e.Timestamp, Kind = e.Kind, Text = e.Text });
        while (_log.Count > 80) _log.RemoveAt(0);
        LogScroll.ScrollToBottom();
    }

    public void UpdateStats()
    {
        bool admin = PrivilegeManager.IsElevated;
        StatPriv.Text = admin ? "ADMIN ✓" : "USER";
        StatPriv.Foreground = admin
            ? (Brush)Application.Current.Resources["Green"]
            : (Brush)Application.Current.Resources["Amber"];
        bool seDebug = PrivilegeManager.TryEnableDebugPrivilege();
        StatPrivSub.Text = seDebug ? "SeDebug enabled" : "SeDebug unavailable";

        bool pipe = PipeClient.IsServiceAvailable(300);
        StatPipe.Text = pipe ? "PIPE OK" : "OFFLINE";
        StatPipe.Foreground = pipe
            ? (Brush)Application.Current.Resources["Green"]
            : (Brush)Application.Current.Resources["Fg4"];
        StatPipeSub.Text = pipe ? "\\\\.\\pipe\\sfk · LocalSystem" : "helper service not running";

        StatThreats.Text = _threats.Count.ToString();
        StatThreats.Foreground = _threats.Count > 0
            ? (Brush)Application.Current.Resources["Accent2"]
            : (Brush)Application.Current.Resources["Green"];

        if (_threats.Count > 0)
        {
            int regCount = _threats.Count(t => t.Surface == "registry");
            int procCount = _threats.Count(t => t.Surface == "process");
            StatThreatsSub.Text = $"{procCount} procs · {regCount} reg";
        }
        else
        {
            StatThreatsSub.Text = _lastSweep.HasValue ? "clean baseline" : "awaiting scan";
        }

        if (_lastSweep.HasValue)
        {
            var span = DateTime.Now - _lastSweep.Value;
            StatLastSweep.Text = span.TotalMinutes < 1 ? "<1m"
                : span.TotalMinutes < 60 ? $"{(int)span.TotalMinutes}m"
                : $"{(int)span.TotalHours}h";
            StatLastSweepSub.Text = $"{_lastSweep.Value:HH:mm:ss}";
        }
        else
        {
            StatLastSweep.Text = "—";
            StatLastSweepSub.Text = "never";
        }

        ThreatsBadge.Text = _threats.Count == 0 ? "none" : $"{_threats.Count} active";
        ThreatsEmpty.Visibility = _threats.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => UpdateStats();

    private void FullSweep_Click(object sender, RoutedEventArgs e)
    {
        OnAction?.Invoke("full sweep started");
        OperatorLog.Append(OperatorLog.Kind.Info, "full sweep · scanning registry + suspicious procs");

        Task.Run(() =>
        {
            // Registry scan
            var suspicious = RegistryCleaner.ScanSuspicious();

            // Suspicious processes: unsigned exes living in user-temp / appdata-roaming
            var procs = ProcessKiller.ListProcesses();
            var suspProcs = procs.Where(p =>
                !string.IsNullOrEmpty(p.FilePath) &&
                (p.FilePath!.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                 p.FilePath.Contains("\\AppData\\Roaming\\Temp", StringComparison.OrdinalIgnoreCase) ||
                 p.FilePath.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase))
            ).Take(10).ToList();

            Dispatcher.Invoke(() =>
            {
                _threats.Clear();
                foreach (var p in suspProcs)
                {
                    _threats.Add(new ThreatRow
                    {
                        Subject = $"{p.Name} ({p.Pid})",
                        Surface = "process",
                        Verdict = "Temp-dir image"
                    });
                }
                foreach (var r in suspicious)
                {
                    var keyLeaf = r.HivePath.Split('\\').LastOrDefault() ?? r.HivePath;
                    _threats.Add(new ThreatRow
                    {
                        Subject = $"{keyLeaf}\\{r.ValueName}",
                        Surface = "registry",
                        Verdict = TrimReason(r.Reason)
                    });
                }
                _lastSweep = DateTime.Now;
                UpdateStats();
                OperatorLog.Append(_threats.Count > 0 ? OperatorLog.Kind.Warn : OperatorLog.Kind.Ok,
                    $"full sweep → {_threats.Count} threats ({suspProcs.Count} procs · {suspicious.Count} reg)");
                OnAction?.Invoke($"full sweep → {_threats.Count} threats");
            });
        });
    }

    private static string TrimReason(string? reason)
    {
        if (string.IsNullOrEmpty(reason)) return "Suspect";
        return reason.Length > 32 ? reason[..29] + "…" : reason;
    }

    private void GoProcesses_Click(object sender, RoutedEventArgs e) => OnNavigate?.Invoke("processes");
    private void GoServices_Click(object sender, RoutedEventArgs e)  => OnNavigate?.Invoke("services");
    private void GoFiles_Click(object sender, RoutedEventArgs e)     => OnNavigate?.Invoke("files");
    private void GoRegistry_Click(object sender, RoutedEventArgs e)  => OnNavigate?.Invoke("registry");
    private void GoAnalyze_Click(object sender, RoutedEventArgs e)   => OnNavigate?.Invoke("analyze");

    private void Emergency_Click(object sender, RoutedEventArgs e)
    {
        OnAction?.Invoke("emergency · navigating to processes for review");
        OperatorLog.Append(OperatorLog.Kind.Warn, "emergency action → review threats list before mass kill");
        OnNavigate?.Invoke("processes");
    }
}
