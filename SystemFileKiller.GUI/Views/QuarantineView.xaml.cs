using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using SystemFileKiller.Core;
using MessageBox = System.Windows.MessageBox;

namespace SystemFileKiller.GUI.Views;

public partial class QuarantineView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;

    private readonly ObservableCollection<ItemRow> _rows = new();

    public QuarantineView()
    {
        InitializeComponent();
        ItemsGrid.ItemsSource = _rows;
        Loaded += (_, _) => Refresh_Click(this, new RoutedEventArgs());
    }

    public sealed class ItemRow
    {
        public string Id { get; init; } = "";
        public string OriginalPath { get; init; } = "";
        public string QuarantinedAt { get; init; } = "";
        public string Kind { get; init; } = "";
        public long SizeBytes { get; init; }
        public string SizeText => SizeBytes switch
        {
            < 1024 => $"{SizeBytes} B",
            < 1024 * 1024 => $"{SizeBytes / 1024.0:F1} KB",
            < 1024 * 1024 * 1024 => $"{SizeBytes / (1024.0 * 1024):F1} MB",
            _ => $"{SizeBytes / (1024.0 * 1024 * 1024):F2} GB",
        };
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        Task.Run(() =>
        {
            var items = QuarantineManager.ListItems();
            Dispatcher.Invoke(() =>
            {
                _rows.Clear();
                foreach (var i in items)
                {
                    _rows.Add(new ItemRow
                    {
                        Id = i.Id,
                        OriginalPath = i.OriginalPath,
                        QuarantinedAt = i.QuarantinedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                        Kind = i.WasDirectory ? "dir" : "file",
                        SizeBytes = i.OriginalSizeBytes,
                    });
                }
                OnAction?.Invoke($"Quarantine: {_rows.Count} item(s)");
            });
        });
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { CheckFileExists = true, Title = "Select file to quarantine" };
        if (dlg.ShowDialog() == true) PathBox.Text = dlg.FileName;
    }

    private void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        var path = (PathBox.Text ?? "").Trim();
        if (string.IsNullOrEmpty(path)) { OnAction?.Invoke("Quarantine: path required"); return; }
        var ok = MessageBox.Show($"Quarantine '{path}'?\n\nThis will archive then remove the original.",
            "Confirm quarantine", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (ok != MessageBoxResult.Yes) return;
        Task.Run(() =>
        {
            var (r, msg, item) = QuarantineManager.Quarantine(path);
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"Quarantine {r}: {msg}");
                if (item is not null) Refresh_Click(this, new RoutedEventArgs());
            });
        });
    }

    private void Restore_Click(object sender, RoutedEventArgs e)
    {
        var sel = ItemsGrid.SelectedItems.Cast<ItemRow>().ToList();
        if (sel.Count == 0) { OnAction?.Invoke("Quarantine: select rows first"); return; }
        Task.Run(() =>
        {
            int ok = 0;
            foreach (var r in sel)
            {
                var (res, _) = QuarantineManager.Restore(r.Id);
                if (res == QuarantineResult.Success) ok++;
            }
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"Restored {ok}/{sel.Count} item(s)");
                Refresh_Click(this, new RoutedEventArgs());
            });
        });
    }

    private void Purge_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(PurgeDaysBox.Text, out var days) || days < 0) days = 0;
        var label = days == 0 ? "ALL" : $"older than {days} day(s)";
        var ok = MessageBox.Show($"Permanently purge quarantine items {label}?\n\nIrreversible.",
            "Confirm purge", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (ok != MessageBoxResult.Yes) return;
        Task.Run(() =>
        {
            var (res, msg, removed) = QuarantineManager.Purge(days);
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"Purge: {removed} bucket(s) removed");
                Refresh_Click(this, new RoutedEventArgs());
            });
        });
    }
}
