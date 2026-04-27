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
using Color = System.Windows.Media.Color;
using SolidColorBrush = System.Windows.Media.SolidColorBrush;
using MessageBox = System.Windows.MessageBox;

namespace SystemFileKiller.GUI.Views;

public partial class ServicesView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;
    public event Action<int /*visible*/, int /*total*/>? OnCountsChanged;

    private List<SvcRow> _all = new();
    private string _filter = "";
    private bool _runningOnly;

    public ServicesView()
    {
        InitializeComponent();
    }

    public sealed class SvcRow
    {
        public string Name { get; init; } = "";
        public string DisplayName { get; init; } = "";
        public string Status { get; init; } = "";
        public int ProcessId { get; init; }
        public string PidDisplay => ProcessId == 0 ? "—" : ProcessId.ToString();
        public string StatusBadge => Status.Equals("Running", StringComparison.OrdinalIgnoreCase) ? "● RUN" : "○ STOP";
        public Brush StatusBg
        {
            get
            {
                var bg = (Brush)System.Windows.Application.Current.Resources["Bg2"];
                if (Status.Equals("Running", StringComparison.OrdinalIgnoreCase))
                {
                    var c = ((SolidColorBrush)System.Windows.Application.Current.Resources["Green"]).Color;
                    return new SolidColorBrush(Color.FromArgb(0x2A, c.R, c.G, c.B));
                }
                return bg;
            }
        }
        public Brush StatusBorder
        {
            get
            {
                if (Status.Equals("Running", StringComparison.OrdinalIgnoreCase))
                    return (Brush)System.Windows.Application.Current.Resources["Green"];
                return (Brush)System.Windows.Application.Current.Resources["Line2"];
            }
        }
        public Brush StatusFg
        {
            get
            {
                if (Status.Equals("Running", StringComparison.OrdinalIgnoreCase))
                    return (Brush)System.Windows.Application.Current.Resources["Green"];
                return (Brush)System.Windows.Application.Current.Resources["Fg3"];
            }
        }
    }

    public void RefreshList()
    {
        Task.Run(() =>
        {
            var raw = ServiceManager.ListServices(false);
            var rows = raw.Select(s => new SvcRow
            {
                Name = s.Name,
                DisplayName = s.DisplayName,
                Status = s.Status,
                ProcessId = s.ProcessId
            }).ToList();
            Dispatcher.Invoke(() =>
            {
                _all = rows;
                ApplyFilter();
            });
        });
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshList();
    private void Filter_TextChanged(object sender, TextChangedEventArgs e)
    {
        _filter = FilterBox.Text?.Trim() ?? "";
        ApplyFilter();
    }
    private void RunningOnly_Click(object sender, RoutedEventArgs e)
    {
        _runningOnly = ChkRunningOnly.IsChecked == true;
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        IEnumerable<SvcRow> filtered = _all;
        if (_runningOnly) filtered = filtered.Where(s => s.Status.Equals("Running", StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrEmpty(_filter))
        {
            var q = _filter;
            filtered = filtered.Where(s =>
                s.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                s.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase));
        }
        var list = filtered.ToList();
        Grid.ItemsSource = list;
        var running = _all.Count(s => s.Status.Equals("Running", StringComparison.OrdinalIgnoreCase));
        SubText.Text = $"{_all.Count} services · {running} running · {list.Count} shown";
        OnCountsChanged?.Invoke(list.Count, _all.Count);
    }

    private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Grid.SelectedItem is SvcRow s)
        {
            DetName.Text = s.Name;
            DetDisplay.Text = s.DisplayName;
            DetPid.Text = s.PidDisplay;
            DetState.Text = s.Status;
            DetStatusText.Text = s.StatusBadge;
            DetStatusText.Foreground = s.StatusFg;
            DetStatusBadge.Background = s.StatusBg;
            DetStatusBadge.BorderBrush = s.StatusBorder;
        }
        else
        {
            DetName.Text = "no selection";
            DetDisplay.Text = DetPid.Text = DetState.Text = "—";
            DetStatusText.Text = "—";
        }
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is not SvcRow s) return;
        if (MessageBox.Show($"Stop service '{s.Name}'?", "Confirm", MessageBoxButton.YesNo,
            MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        OnAction?.Invoke($"SCM.Stop {s.Name} · pending");
        Task.Run(() =>
        {
            var r = ServiceManager.StopService(s.Name);
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"SCM.Stop {s.Name} → {r}");
                RefreshList();
            });
        });
    }

    private void Start_Click(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is not SvcRow s) return;
        OnAction?.Invoke($"SCM.Start {s.Name} · pending");
        Task.Run(() =>
        {
            var r = ServiceManager.StartService(s.Name);
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"SCM.Start {s.Name} → {r}");
                RefreshList();
            });
        });
    }

    private void Restart_Click(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is not SvcRow s) return;
        OnAction?.Invoke($"SCM.Restart {s.Name} · pending");
        Task.Run(() =>
        {
            var stop = ServiceManager.StopService(s.Name);
            ServiceOpResult start = ServiceOpResult.Failed;
            if (stop is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState)
                start = ServiceManager.StartService(s.Name);
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"SCM.Restart {s.Name} → stop={stop} start={start}");
                RefreshList();
            });
        });
    }
}
