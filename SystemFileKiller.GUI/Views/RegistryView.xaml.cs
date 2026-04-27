using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SystemFileKiller.Core;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using MessageBox = System.Windows.MessageBox;

namespace SystemFileKiller.GUI.Views;

public partial class RegistryView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;
    public event Action<int /*visible*/, int /*total*/>? OnCountsChanged;
    public event Action<int /*suspicious*/>? OnSuspiciousCountChanged;

    private List<RegRow> _all = new();
    private bool _suspiciousOnly;

    public RegistryView()
    {
        InitializeComponent();
    }

    public sealed class RegRow
    {
        public RegistryEntry Entry { get; init; } = new("", "", null, null);
        public string Hive => Entry.HivePath.Split('\\', 2)[0];
        public string KeyPath
        {
            get
            {
                var parts = Entry.HivePath.Split('\\', 2);
                return parts.Length > 1 ? parts[1] : "";
            }
        }
        public string ValueName => Entry.ValueName;
        public string Value => Entry.ValueData ?? "";
        public string? Reason => Entry.Reason;
        public string VerdictLabel => Reason != null ? "SUSPECT" : "CLEAN";
        public Brush VerdictBg
        {
            get
            {
                var key = Reason != null ? "AccentGlow" : "Bg2";
                return (Brush)System.Windows.Application.Current.Resources[key];
            }
        }
        public Brush VerdictBorder
        {
            get
            {
                var key = Reason != null ? "Accent" : "Line2";
                return (Brush)System.Windows.Application.Current.Resources[key];
            }
        }
        public Brush VerdictFg
        {
            get
            {
                var key = Reason != null ? "Accent2" : "Green";
                return (Brush)System.Windows.Application.Current.Resources[key];
            }
        }
    }

    private void ScanAll_Click(object sender, RoutedEventArgs e) => Scan();

    private void ToggleSuspicious_Click(object sender, RoutedEventArgs e)
    {
        _suspiciousOnly = !_suspiciousOnly;
        BtnSuspicious.Content = _suspiciousOnly ? "Showing suspicious" : "Show suspicious only";
        ApplyFilter();
    }

    private void Scan()
    {
        OnAction?.Invoke("registry scan · all persistence locations");
        Task.Run(() =>
        {
            var raw = RegistryCleaner.ScanPersistenceLocations();
            var rows = raw.Select(r => new RegRow { Entry = r }).ToList();
            Dispatcher.Invoke(() =>
            {
                _all = rows;
                ApplyFilter();
                UpdateStats();
                OnAction?.Invoke($"registry scan → {rows.Count} entries · {rows.Count(r => r.Reason != null)} suspicious");
            });
        });
    }

    private void ApplyFilter()
    {
        var list = _suspiciousOnly ? _all.Where(r => r.Reason != null).ToList() : _all;
        Grid.ItemsSource = list;
        SubText.Text = $"{_all.Count} entries scanned · {_all.Count(r => r.Reason != null)} flagged suspicious · {list.Count} shown";
        OnCountsChanged?.Invoke(list.Count, _all.Count);
    }

    private void UpdateStats()
    {
        int hklm = _all.Count(r => r.Hive == "HKLM" && r.Entry.HivePath.Contains("\\Run", StringComparison.OrdinalIgnoreCase));
        int hkcu = _all.Count(r => r.Hive == "HKCU" && r.Entry.HivePath.Contains("\\Run", StringComparison.OrdinalIgnoreCase));
        int winlogon = _all.Count(r => r.Entry.HivePath.Contains("Winlogon", StringComparison.OrdinalIgnoreCase) || r.Entry.ValueName == "Load");
        int susp = _all.Count(r => r.Reason != null);
        StatHKLM.Text = hklm.ToString();
        StatHKCU.Text = hkcu.ToString();
        StatWinlogon.Text = winlogon.ToString();
        StatSusp.Text = susp.ToString();
        OnSuspiciousCountChanged?.Invoke(susp);
    }

    private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Grid.SelectedItems.Count == 1 && Grid.SelectedItems[0] is RegRow r)
        {
            DetVerdictText.Text = r.VerdictLabel;
            DetVerdictText.Foreground = r.VerdictFg;
            DetVerdictBadge.Background = r.VerdictBg;
            DetVerdictBadge.BorderBrush = r.VerdictBorder;
            DetValueName.Text = r.ValueName;
            DetHive.Text = r.Hive;
            DetKey.Text = r.KeyPath;
            DetName.Text = r.ValueName;
            DetValue.Text = r.Value;
            if (r.Reason != null)
            {
                ReasonPanel.Visibility = Visibility.Visible;
                DetReason.Text = r.Reason;
            }
            else
            {
                ReasonPanel.Visibility = Visibility.Collapsed;
            }
        }
        else
        {
            DetVerdictText.Text = "—";
            DetValueName.Text = Grid.SelectedItems.Count > 1 ? $"{Grid.SelectedItems.Count} selected" : "no selection";
            DetHive.Text = DetKey.Text = DetName.Text = DetValue.Text = "—";
            ReasonPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void RemoveSelected_Click(object sender, RoutedEventArgs e)
    {
        var sel = Grid.SelectedItems.Cast<RegRow>().ToList();
        if (sel.Count == 0) return;
        if (MessageBox.Show($"Remove {sel.Count} registry entries?\n\nThis cannot be undone.", "Confirm",
            MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        Task.Run(() =>
        {
            int removed = RegistryCleaner.RemoveEntries(sel.Select(r => r.Entry).ToList());
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"registry remove → {removed}/{sel.Count}");
                Scan();
            });
        });
    }

    private void PurgeSuspicious_Click(object sender, RoutedEventArgs e)
    {
        var susp = _all.Where(r => r.Reason != null).Select(r => r.Entry).ToList();
        if (susp.Count == 0) return;
        if (MessageBox.Show($"Remove ALL {susp.Count} suspicious entries?\n\nThis cannot be undone.", "Confirm purge",
            MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        Task.Run(() =>
        {
            int removed = RegistryCleaner.RemoveEntries(susp);
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"registry purge → {removed}/{susp.Count}");
                Scan();
            });
        });
    }
}
