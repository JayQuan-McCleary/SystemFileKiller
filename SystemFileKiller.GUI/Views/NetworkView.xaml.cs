using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using SystemFileKiller.Core;

namespace SystemFileKiller.GUI.Views;

public partial class NetworkView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;

    private readonly ObservableCollection<ConnRow> _rows = new();

    public NetworkView()
    {
        InitializeComponent();
        ConnGrid.ItemsSource = _rows;
        FilterBox.TextChanged += (_, _) => Refresh_Click(this, new RoutedEventArgs());
        EstablishedOnly.Checked += (_, _) => Refresh_Click(this, new RoutedEventArgs());
        EstablishedOnly.Unchecked += (_, _) => Refresh_Click(this, new RoutedEventArgs());
        Loaded += (_, _) => Refresh_Click(this, new RoutedEventArgs());
    }

    public sealed class ConnRow
    {
        public string Protocol { get; init; } = "";
        public string State { get; init; } = "";
        public string LocalEndpoint { get; init; } = "";
        public string RemoteEndpoint { get; init; } = "";
        public int OwningPid { get; init; }
        public string OwningProcessName { get; init; } = "";
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        var establishedOnly = EstablishedOnly.IsChecked == true;
        var filter = (FilterBox.Text ?? "").Trim();
        Task.Run(() =>
        {
            var conns = NetConnUtil.ListTcp();
            Dispatcher.Invoke(() =>
            {
                _rows.Clear();
                int total = 0;
                foreach (var c in conns)
                {
                    total++;
                    if (establishedOnly && !string.Equals(c.State, "ESTABLISHED", StringComparison.OrdinalIgnoreCase)) continue;
                    var nameMatch = string.IsNullOrEmpty(filter)
                        || (c.OwningProcessName ?? "").Contains(filter, StringComparison.OrdinalIgnoreCase)
                        || c.RemoteAddress.Contains(filter, StringComparison.OrdinalIgnoreCase)
                        || c.LocalAddress.Contains(filter, StringComparison.OrdinalIgnoreCase)
                        || c.OwningPid.ToString().Contains(filter, StringComparison.OrdinalIgnoreCase);
                    if (!nameMatch) continue;
                    _rows.Add(new ConnRow
                    {
                        Protocol = c.Protocol,
                        State = c.State,
                        LocalEndpoint = $"{c.LocalAddress}:{c.LocalPort}",
                        RemoteEndpoint = $"{c.RemoteAddress}:{c.RemotePort}",
                        OwningPid = c.OwningPid,
                        OwningProcessName = c.OwningProcessName ?? "(unknown)",
                    });
                }
                CountLabel.Text = $"{_rows.Count} of {total} shown";
                OnAction?.Invoke($"Network: {_rows.Count}/{total} TCP connections");
            });
        });
    }
}
