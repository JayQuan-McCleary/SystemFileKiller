using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using SystemFileKiller.Core;
using MessageBox = System.Windows.MessageBox;
using Clipboard = System.Windows.Clipboard;

namespace SystemFileKiller.GUI;

public partial class MainWindow : Window
{
    private List<ProcessInfo> _allProcesses = [];
    private List<RegistryEntry> _allRegistryEntries = [];

    public MainWindow()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            var admin = App.IsRunningAsAdmin();
            StatusText.Text = admin
                ? "Running as Administrator. Full functionality available."
                : "Running WITHOUT admin. Some features may not work. Restart as admin for full access.";
            StatusText.Foreground = admin
                ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x4e, 0xc9, 0xb0))
                : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xe9, 0x45, 0x60));
            RefreshProcesses();
        };
    }

    // ── Process Tab ──

    private void ProcessRefresh_Click(object sender, RoutedEventArgs e) => RefreshProcesses();

    private void RefreshProcesses()
    {
        SetStatus("Refreshing process list...");
        Task.Run(() =>
        {
            var procs = ProcessKiller.ListProcesses();
            Dispatcher.Invoke(() =>
            {
                _allProcesses = procs;
                ApplyProcessFilter();
                SetStatus($"Loaded {procs.Count} processes.");
            });
        });
    }

    private void ProcessFilter_TextChanged(object sender, TextChangedEventArgs e) => ApplyProcessFilter();

    private void ApplyProcessFilter()
    {
        var filter = ProcessFilterBox.Text.Trim().ToLowerInvariant();
        var filtered = string.IsNullOrEmpty(filter)
            ? _allProcesses
            : _allProcesses.Where(p =>
                p.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                p.Pid.ToString().Contains(filter) ||
                (p.FilePath?.Contains(filter, StringComparison.OrdinalIgnoreCase) == true))
                .ToList();

        ProcessGrid.ItemsSource = filtered;
        ProcessCountText.Text = $"{filtered.Count} / {_allProcesses.Count} processes";
    }

    private void ProcessKill_Click(object sender, RoutedEventArgs e) => KillSelectedProcesses(false);
    private void ProcessKillTree_Click(object sender, RoutedEventArgs e) => KillSelectedProcesses(true);

    private void KillSelectedProcesses(bool tree)
    {
        var selected = ProcessGrid.SelectedItems.Cast<ProcessInfo>().ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show("Select one or more processes first.", "No Selection",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var names = string.Join(", ", selected.Select(p => $"{p.Name} ({p.Pid})"));
        var msg = tree
            ? $"Kill these processes and all their children?\n\n{names}"
            : $"Force-kill these processes?\n\n{names}";

        if (MessageBox.Show(msg, "Confirm Kill", MessageBoxButton.YesNo,
            MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        int success = 0, fail = 0;
        foreach (var proc in selected)
        {
            var result = ProcessKiller.ForceKill(proc.Pid, tree);
            if (result == KillResult.Success) success++;
            else fail++;
        }

        SetStatus($"Killed: {success}, Failed: {fail}");
        RefreshProcesses();
    }

    private void ProcessCopyPid_Click(object sender, RoutedEventArgs e)
    {
        if (ProcessGrid.SelectedItem is ProcessInfo proc)
            Clipboard.SetText(proc.Pid.ToString());
    }

    private void ProcessOpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (ProcessGrid.SelectedItem is ProcessInfo proc && proc.FilePath != null)
        {
            var dir = Path.GetDirectoryName(proc.FilePath);
            if (dir != null && Directory.Exists(dir))
                Process.Start("explorer.exe", $"/select,\"{proc.FilePath}\"");
        }
    }

    // ── File Tab ──

    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Filter = "All Files|*.*" };
        if (dlg.ShowDialog() == true)
            FilePathBox.Text = dlg.FileName;
    }

    private void BrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new System.Windows.Forms.FolderBrowserDialog();
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            FilePathBox.Text = dlg.SelectedPath;
    }

    private void FileUnlock_Click(object sender, RoutedEventArgs e)
    {
        var path = FilePathBox.Text.Trim();
        if (string.IsNullOrEmpty(path)) { AppendFileOutput("Enter a file path first."); return; }

        SetStatus($"Unlocking: {path}");
        Task.Run(() =>
        {
            var result = FileDestroyer.UnlockFile(path);
            Dispatcher.Invoke(() =>
            {
                if (result.HandlesFound == 0)
                {
                    AppendFileOutput($"No locking handles found for: {path}");
                }
                else
                {
                    AppendFileOutput($"Found {result.HandlesFound} handle(s) for: {path}");
                    foreach (var (pid, name) in result.LockingProcesses)
                        AppendFileOutput($"  PID {pid} ({name ?? "unknown"})");
                    AppendFileOutput($"Closed: {result.HandlesClosed}/{result.HandlesFound}");
                }
                SetStatus("Unlock complete.");
            });
        });
    }

    private void FileForceDelete_Click(object sender, RoutedEventArgs e)
    {
        var path = FilePathBox.Text.Trim();
        if (string.IsNullOrEmpty(path)) { AppendFileOutput("Enter a file path first."); return; }

        if (MessageBox.Show($"Force-delete this file?\n\n{path}", "Confirm Delete",
            MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        SetStatus($"Deleting: {path}");
        Task.Run(() =>
        {
            var (result, message) = FileDestroyer.ForceDelete(path);
            Dispatcher.Invoke(() =>
            {
                AppendFileOutput(message);
                SetStatus(message);
            });
        });
    }

    private void FileDeleteDir_Click(object sender, RoutedEventArgs e)
    {
        var path = FilePathBox.Text.Trim();
        if (string.IsNullOrEmpty(path)) { AppendFileOutput("Enter a directory path first."); return; }

        if (MessageBox.Show($"Force-delete this entire directory?\n\n{path}\n\nThis cannot be undone!",
            "Confirm Directory Delete", MessageBoxButton.YesNo,
            MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        SetStatus($"Deleting directory: {path}");
        Task.Run(() =>
        {
            var (result, message) = FileDestroyer.ForceDeleteDirectory(path);
            Dispatcher.Invoke(() =>
            {
                AppendFileOutput(message);
                SetStatus(message);
            });
        });
    }

    private void FileRebootDelete_Click(object sender, RoutedEventArgs e)
    {
        var path = FilePathBox.Text.Trim();
        if (string.IsNullOrEmpty(path)) { AppendFileOutput("Enter a file path first."); return; }

        SetStatus($"Scheduling reboot delete: {path}");
        var (result, message) = FileDestroyer.ScheduleRebootDelete(path);
        AppendFileOutput(message);
        SetStatus(message);
    }

    private void AppendFileOutput(string text)
    {
        var time = DateTime.Now.ToString("HH:mm:ss");
        FileOutputText.Text += $"[{time}] {text}\n";
    }

    // ── Registry Tab ──

    private void RegistryScanAll_Click(object sender, RoutedEventArgs e) => ScanRegistry(false);
    private void RegistryScanSuspicious_Click(object sender, RoutedEventArgs e) => ScanRegistry(true);

    private void ScanRegistry(bool suspiciousOnly)
    {
        SetStatus("Scanning registry...");
        Task.Run(() =>
        {
            var entries = suspiciousOnly
                ? RegistryCleaner.ScanSuspicious()
                : RegistryCleaner.ScanPersistenceLocations();

            Dispatcher.Invoke(() =>
            {
                _allRegistryEntries = entries;
                RegistryGrid.ItemsSource = entries;
                var suspicious = entries.Count(e => e.Reason != null);
                RegistryCountText.Text = $"{entries.Count} entries ({suspicious} suspicious)";
                SetStatus($"Registry scan complete. {entries.Count} entries found.");
            });
        });
    }

    private void RegistryRemoveSelected_Click(object sender, RoutedEventArgs e)
    {
        var selected = RegistryGrid.SelectedItems.Cast<RegistryEntry>().ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show("Select entries to remove.", "No Selection",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MessageBox.Show($"Remove {selected.Count} registry entries?\n\nThis cannot be undone!",
            "Confirm Remove", MessageBoxButton.YesNo,
            MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        int removed = RegistryCleaner.RemoveEntries(selected);
        SetStatus($"Removed {removed}/{selected.Count} entries.");
        ScanRegistry(false);
    }

    private void RegistryRemoveAllSuspicious_Click(object sender, RoutedEventArgs e)
    {
        var suspicious = _allRegistryEntries.Where(e => e.Reason != null).ToList();
        if (suspicious.Count == 0)
        {
            MessageBox.Show("No suspicious entries found.", "Clean",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MessageBox.Show($"Remove ALL {suspicious.Count} suspicious entries?\n\nThis cannot be undone!",
            "Confirm Remove All", MessageBoxButton.YesNo,
            MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        int removed = RegistryCleaner.RemoveEntries(suspicious);
        SetStatus($"Removed {removed}/{suspicious.Count} suspicious entries.");
        ScanRegistry(false);
    }

    // ── Helpers ──

    private void SetStatus(string text)
    {
        StatusText.Text = text;
    }
}
