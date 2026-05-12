using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using SystemFileKiller.Core;
using MessageBox = System.Windows.MessageBox;

namespace SystemFileKiller.GUI.Views;

public partial class PersistenceView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;

    private readonly ObservableCollection<WmiRow> _wmi = new();
    private readonly ObservableCollection<HostsRow> _hosts = new();

    public PersistenceView()
    {
        InitializeComponent();
        WmiGrid.ItemsSource = _wmi;
        HostsGrid.ItemsSource = _hosts;
        Loaded += (_, _) => HostsRefresh_Click(this, new RoutedEventArgs());
    }

    public sealed class WmiRow
    {
        public string FilterName { get; init; } = "";
        public string ConsumerName { get; init; } = "";
        public string ConsumerType { get; init; } = "";
        public string CmdOrPath { get; init; } = "";
    }

    public sealed class HostsRow
    {
        public int LineNumber { get; init; }
        public string Address { get; init; } = "";
        public string Hostname { get; init; } = "";
        public string Comment { get; init; } = "";
    }

    // ── WMI tab ──
    private void WmiScan_Click(object sender, RoutedEventArgs e)
    {
        WmiCount.Text = "scanning…";
        Task.Run(() =>
        {
            var subs = WmiPersistenceUtil.Scan();
            Dispatcher.Invoke(() =>
            {
                _wmi.Clear();
                foreach (var s in subs)
                {
                    _wmi.Add(new WmiRow
                    {
                        FilterName = s.FilterName,
                        ConsumerName = s.ConsumerName,
                        ConsumerType = s.ConsumerType,
                        CmdOrPath = string.IsNullOrEmpty(s.CommandLineTemplate) ? s.ExecutablePath : s.CommandLineTemplate,
                    });
                }
                WmiCount.Text = $"{_wmi.Count} subscription(s)";
                OnAction?.Invoke($"WMI persistence: {_wmi.Count} found");
            });
        });
    }

    private void WmiRemove_Click(object sender, RoutedEventArgs e)
    {
        var sel = WmiGrid.SelectedItems.Cast<WmiRow>().ToList();
        if (sel.Count == 0) { OnAction?.Invoke("WMI: select rows first"); return; }
        var ok = MessageBox.Show($"Remove {sel.Count} WMI subscription(s)?", "Confirm",
            MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (ok != MessageBoxResult.Yes) return;
        Task.Run(() =>
        {
            int removed = 0;
            foreach (var r in sel)
            {
                var (k, _) = WmiPersistenceUtil.RemoveByConsumerName(r.ConsumerName);
                if (k) removed++;
            }
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"WMI removed: {removed}/{sel.Count}");
                WmiScan_Click(this, new RoutedEventArgs());
            });
        });
    }

    // ── Hosts tab ──
    private void HostsRefresh_Click(object sender, RoutedEventArgs e)
    {
        Task.Run(() =>
        {
            var entries = HostsFileUtil.ReadEntries();
            Dispatcher.Invoke(() =>
            {
                _hosts.Clear();
                foreach (var h in entries)
                    _hosts.Add(new HostsRow { LineNumber = h.LineNumber, Address = h.Address, Hostname = h.Hostname, Comment = h.Comment ?? "" });
                HostsCount.Text = $"{_hosts.Count} non-comment entr{(_hosts.Count == 1 ? "y" : "ies")}";
                OnAction?.Invoke($"Hosts: {_hosts.Count} entries");
            });
        });
    }

    private void HostsRemove_Click(object sender, RoutedEventArgs e)
    {
        var pat = (HostsPatternBox.Text ?? "").Trim();
        if (string.IsNullOrEmpty(pat)) { OnAction?.Invoke("Hosts: pattern required"); return; }
        var ok = MessageBox.Show($"Remove all hosts entries matching /{pat}/?\n\nBackup saved as hosts.sfk-bak.",
            "Confirm hosts edit", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (ok != MessageBoxResult.Yes) return;
        Task.Run(() =>
        {
            var (success, msg, removed) = HostsFileUtil.RemoveMatching(pat);
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"Hosts remove: {removed} entries — {msg}");
                HostsRefresh_Click(this, new RoutedEventArgs());
            });
        });
    }

    // ── Restore points tab ──
    private void RpCreate_Click(object sender, RoutedEventArgs e)
    {
        var desc = (RpDescBox.Text ?? "SFK checkpoint").Trim();
        RpStatus.Text = "creating checkpoint…";
        Task.Run(() =>
        {
            var (r, msg) = RestorePointUtil.Create(desc);
            Dispatcher.Invoke(() =>
            {
                RpStatus.Text = $"{r}: {msg}";
                OnAction?.Invoke($"Restore point: {r}");
            });
        });
    }
}
