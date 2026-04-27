using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SystemFileKiller.Core;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using MessageBox = System.Windows.MessageBox;
using Clipboard = System.Windows.Clipboard;

namespace SystemFileKiller.GUI.Views;

public partial class ProcessesView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;
    public event Action<int /*visible*/, int /*total*/>? OnCountsChanged;

    private List<ProcRow> _all = new();
    private string _filter = "";
    private readonly ObservableCollection<TraceLine> _trace = new();

    public ProcessesView()
    {
        InitializeComponent();
        TraceList.ItemsSource = _trace;
    }

    public sealed class ProcRow
    {
        public int Pid { get; init; }
        public string Name { get; init; } = "";
        public string? FilePath { get; init; }
        public long MemoryMB { get; init; }
        public string? Description { get; init; }
        public string MemoryDisplay => $"{MemoryMB} MB";
    }

    public sealed class TraceLine
    {
        public string Number { get; init; } = "";
        public string Label { get; init; } = "";
        public string Result { get; init; } = "";
        public Brush StatusBrush { get; init; } = System.Windows.Media.Brushes.Gray;
    }

    public void RefreshList()
    {
        Task.Run(() =>
        {
            var raw = ProcessKiller.ListProcesses();
            var rows = raw.Select(p => new ProcRow
            {
                Pid = p.Pid,
                Name = p.Name,
                FilePath = p.FilePath,
                MemoryMB = p.MemoryMB,
                Description = p.Description
            }).ToList();
            Dispatcher.Invoke(() =>
            {
                _all = rows;
                ApplyFilter();
                UpdateStatStrip();
            });
        });
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshList();

    private void Filter_TextChanged(object sender, TextChangedEventArgs e)
    {
        _filter = FilterBox.Text?.Trim() ?? "";
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        IEnumerable<ProcRow> filtered = _all;
        if (!string.IsNullOrEmpty(_filter))
        {
            var q = _filter;
            filtered = _all.Where(p =>
                p.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                p.Pid.ToString().Contains(q) ||
                (p.FilePath?.Contains(q, StringComparison.OrdinalIgnoreCase) == true));
        }
        var list = filtered.ToList();
        Grid.ItemsSource = list;
        SubText.Text = $"{list.Count} of {_all.Count} listed · {Grid.SelectedItems.Count} selected · " +
                       (PrivilegeManager.TryEnableDebugPrivilege() ? "SeDebugPrivilege ENABLED" : "SeDebugPrivilege OFF");
        OnCountsChanged?.Invoke(list.Count, _all.Count);
    }

    private void UpdateStatStrip()
    {
        StatTotal.Text = _all.Count.ToString();

        bool admin = PrivilegeManager.IsElevated;
        StatPriv.Text = admin ? "ADMIN" : "USER";
        StatPriv.Foreground = admin
            ? (Brush)Application.Current.Resources["Green"]
            : (Brush)Application.Current.Resources["Amber"];

        bool pipe = PipeClient.IsServiceAvailable(300);
        StatPipe.Text = pipe ? "ONLINE" : "OFFLINE";
        StatPipe.Foreground = pipe
            ? (Brush)Application.Current.Resources["Green"]
            : (Brush)Application.Current.Resources["Fg4"];

        // Process working-set sum (≈ memory currently in use by the listed processes)
        var usedGb = _all.Sum(p => (double)p.MemoryMB) / 1024.0;
        // SMBIOS-reported physically installed RAM (the "32 GB on the box" number).
        // Cached on first call — installed RAM doesn't change at runtime.
        if (_installedGb == null) _installedGb = QueryInstalledMemoryGb();
        StatMem.Text = (_installedGb is double t && t > 0)
            ? $"{usedGb:F1} / {t:F0} GB"
            : (usedGb >= 1.0 ? $"{usedGb:F1} GB" : $"{usedGb * 1024:F0} MB");
    }

    private static double? _installedGb;

    /// <summary>
    /// Returns total physically installed RAM in GB (e.g. 32 for two 16-GB DIMMs).
    /// Uses the Win32 SMBIOS-backed API; falls back to WMI-reported OS-visible RAM.
    /// </summary>
    private static double QueryInstalledMemoryGb()
    {
        try
        {
            if (NativeBridge.GetPhysicallyInstalledSystemMemory(out long kb))
                return kb / 1024.0 / 1024.0;
        }
        catch { /* fall through */ }
        try
        {
            using var s = new System.Management.ManagementObjectSearcher(
                "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            foreach (System.Management.ManagementObject obj in s.Get())
            {
                long bytes = Convert.ToInt64(obj["TotalPhysicalMemory"]);
                obj.Dispose();
                return bytes / 1024.0 / 1024.0 / 1024.0;
            }
        }
        catch { /* swallow */ }
        return 0;
    }

    private static class NativeBridge
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetPhysicallyInstalledSystemMemory(out long memoryInKilobytes);
    }

    private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var sel = Grid.SelectedItems.Cast<ProcRow>().ToList();
        SubText.Text = $"{Grid.Items.Count} listed · {sel.Count} selected · " +
                       (PrivilegeManager.TryEnableDebugPrivilege() ? "SeDebugPrivilege ENABLED" : "SeDebugPrivilege OFF");

        if (sel.Count == 1)
        {
            var p = sel[0];
            TargetPidText.Text = $"PID {p.Pid}";
            TargetNameText.Text = p.Name;
            DetPid.Text = p.Pid.ToString();
            DetMem.Text = p.MemoryDisplay;
            DetPath.Text = p.FilePath ?? "—";
            DetDesc.Text = p.Description ?? "—";
            HintText.Text = "Standard user-mode process. Stage 1 should resolve immediately. " +
                            "If it AccessDenies, the ladder walks to Stage 3 (service stop) → Stage 4 (pipe service) → Stage 5 (UAC).";
        }
        else
        {
            TargetPidText.Text = "—";
            TargetNameText.Text = sel.Count == 0 ? "no selection" : $"{sel.Count} processes selected";
            DetPid.Text = DetMem.Text = DetPath.Text = DetDesc.Text = "—";
            HintText.Text = "Select a single process to inspect its escalation ladder.";
        }
    }

    private void Kill_Click(object sender, RoutedEventArgs e) => DoKill(false);
    private void KillTree_Click(object sender, RoutedEventArgs e) => DoKill(true);

    private void DoKill(bool overrideKillTree)
    {
        var sel = Grid.SelectedItems.Cast<ProcRow>().ToList();
        if (sel.Count == 0)
        {
            MessageBox.Show("Select one or more processes first.", "No Selection",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        bool tree = overrideKillTree || ChkKillTree.IsChecked == true;
        bool useElev = ChkUseElevation.IsChecked == true;

        var label = string.Join(", ", sel.Select(p => $"{p.Name} ({p.Pid})"));
        var msg = tree
            ? $"Kill these processes and all their children?\n\n{label}"
            : $"Force-kill these processes?\n\n{label}";

        if (MessageBox.Show(msg, "Confirm Kill", MessageBoxButton.YesNo,
            MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        OnAction?.Invoke($"kill {sel.Count} target(s) · escalation in progress");
        _trace.Clear();

        Task.Run(() =>
        {
            int success = 0, fail = 0;
            KillEscalation lastEsc = new();
            KillResult lastResult = KillResult.Failed;
            foreach (var p in sel)
            {
                var esc = new KillEscalation { AllowUacElevation = useElev };
                var r = ProcessKiller.ForceKill(p.Pid, tree, esc);
                lastEsc = esc;
                lastResult = r;
                if (r is KillResult.Success or KillResult.StoppedViaService
                    or KillResult.StoppedViaPipeService or KillResult.StoppedViaUac) success++;
                else fail++;
            }

            Dispatcher.Invoke(() =>
            {
                PopulateTrace(lastEsc, lastResult);
                OnAction?.Invoke($"KILL {(fail==0?"OK":"PARTIAL")} · success={success} fail={fail}");
                RefreshList();
            });
        });
    }

    private void PopulateTrace(KillEscalation esc, KillResult result)
    {
        _trace.Clear();
        int n = 1;
        var line = (string label, string res, Brush brush) =>
            new TraceLine { Number = n.ToString("D2"), Label = label, Result = res, StatusBrush = brush };

        var green = (Brush)Application.Current.Resources["Green"];
        var red = (Brush)Application.Current.Resources["Accent2"];
        var amber = (Brush)Application.Current.Resources["Amber"];
        var dim = (Brush)Application.Current.Resources["Fg4"];

        foreach (var entry in esc.Trace)
        {
            // entries look like "Stage1:Process.Kill:Success" or "Stage3:StopService:Spooler:AccessDenied"
            var parts = entry.Split(':', 4);
            string label = parts.Length > 1 ? string.Join(":", parts.Take(parts.Length - 1)) : entry;
            string res = parts.Length > 1 ? parts[^1] : "";
            Brush brush = res.ToLowerInvariant() switch
            {
                "success" or "ok" or "alreadyintargetstate" => green,
                "accessdenied" or "failed" => red,
                "skipped" or "unavailable" or "alreadyelevated" => dim,
                _ when res.Contains("Exception") => red,
                _ => amber,
            };
            _trace.Add(line(label, res, brush));
            n++;
        }
        _trace.Add(line("FINAL", result.ToString(),
            result is KillResult.Success or KillResult.StoppedViaService
                or KillResult.StoppedViaPipeService or KillResult.StoppedViaUac ? green : red));
    }

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is ProcRow p && p.FilePath is string path)
        {
            var dir = Path.GetDirectoryName(path);
            if (dir != null && Directory.Exists(dir))
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
        }
    }

    private void CopyPid_Click(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is ProcRow p)
        {
            Clipboard.SetText(p.Pid.ToString());
            OnAction?.Invoke($"PID {p.Pid} copied to clipboard");
        }
    }
}
