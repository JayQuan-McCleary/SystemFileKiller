using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using SystemFileKiller.Core;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using MessageBox = System.Windows.MessageBox;

namespace SystemFileKiller.GUI.Views;

public partial class FilesView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;

    private readonly ObservableCollection<ConsoleLine> _lines = new();
    private readonly ObservableCollection<TraceLine> _stages = new();
    private readonly ObservableCollection<LockerLine> _lockers = new();

    public FilesView()
    {
        InitializeComponent();
        ConsoleList.ItemsSource = _lines;
        StagesList.ItemsSource = _stages;
        LockersList.ItemsSource = _lockers;
        AppendLog("info", "Console initialized");
    }

    public sealed class ConsoleLine
    {
        public DateTime Timestamp { get; init; }
        public string Kind { get; init; } = "INFO";
        public string Text { get; init; } = "";
        public Brush KindBrush { get; init; } = System.Windows.Media.Brushes.Gray;
    }
    public sealed class TraceLine
    {
        public string Number { get; init; } = "";
        public string Label { get; init; } = "";
        public string Result { get; init; } = "";
        public Brush StatusBrush { get; init; } = System.Windows.Media.Brushes.Gray;
    }
    public sealed class LockerLine
    {
        public int Pid { get; init; }
        public string Name { get; init; } = "";
    }

    private void AppendLog(string kind, string text)
    {
        var brush = kind switch
        {
            "ok" => (Brush)Application.Current.Resources["Green"],
            "err" => (Brush)Application.Current.Resources["Accent2"],
            "warn" => (Brush)Application.Current.Resources["Amber"],
            _ => (Brush)Application.Current.Resources["Blue"],
        };
        _lines.Add(new ConsoleLine { Timestamp = DateTime.Now, Kind = $" {kind.ToUpper(),-4} ", Text = text, KindBrush = brush });
        while (_lines.Count > 60) _lines.RemoveAt(0);
        OnAction?.Invoke($"{kind.ToUpper()} {text}");
        ConsoleScroll.ScrollToBottom();
    }

    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Filter = "All Files|*.*" };
        if (dlg.ShowDialog() == true) PathBox.Text = dlg.FileName;
    }
    private void BrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new System.Windows.Forms.FolderBrowserDialog();
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK) PathBox.Text = dlg.SelectedPath;
    }

    private string GetPath() => PathBox.Text?.Trim() ?? "";

    private void Unlock_Click(object sender, RoutedEventArgs e)
    {
        var path = GetPath();
        if (string.IsNullOrEmpty(path)) { AppendLog("err", "Enter a path first"); return; }
        AppendLog("info", $"unlock → scanning handles · {path}");
        Task.Run(() =>
        {
            var r = FileDestroyer.UnlockFile(path);
            Dispatcher.Invoke(() =>
            {
                LastOpTarget.Text = path;
                _lockers.Clear();
                foreach (var (pid, name) in r.LockingProcesses)
                    _lockers.Add(new LockerLine { Pid = pid, Name = name ?? "?" });
                AppendLog(r.HandlesFound == 0 ? "info" : "ok",
                    r.HandlesFound == 0 ? "no locking handles found"
                    : $"unlock → {r.HandlesClosed}/{r.HandlesFound} handles closed");
            });
        });
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        var path = GetPath();
        if (string.IsNullOrEmpty(path)) { AppendLog("err", "Enter a path first"); return; }
        if (MessageBox.Show($"Force-delete this file?\n\n{path}", "Confirm",
            MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        AppendLog("info", $"forceDelete → {path}");
        Task.Run(() =>
        {
            var (result, message) = FileDestroyer.ForceDelete(path);
            Dispatcher.Invoke(() =>
            {
                LastOpTarget.Text = path;
                BuildDeleteTrace(result);
                var kind = result == DeleteResult.Success ? "ok"
                          : result == DeleteResult.ScheduledForReboot ? "warn"
                          : "err";
                AppendLog(kind, message);
            });
        });
    }

    private void DeleteDir_Click(object sender, RoutedEventArgs e)
    {
        var path = GetPath();
        if (string.IsNullOrEmpty(path)) { AppendLog("err", "Enter a path first"); return; }
        if (MessageBox.Show($"Force-delete this entire directory?\n\n{path}\n\nThis cannot be undone.",
            "Confirm wipe", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        AppendLog("warn", $"forceDeleteDirectory → {path}");
        Task.Run(() =>
        {
            var (result, message) = FileDestroyer.ForceDeleteDirectory(path);
            Dispatcher.Invoke(() =>
            {
                LastOpTarget.Text = path;
                BuildDeleteTrace(result);
                var kind = result == DeleteResult.Success ? "ok"
                          : result == DeleteResult.ScheduledForReboot ? "warn" : "err";
                AppendLog(kind, message);
            });
        });
    }

    private void RebootDelete_Click(object sender, RoutedEventArgs e)
    {
        var path = GetPath();
        if (string.IsNullOrEmpty(path)) { AppendLog("err", "Enter a path first"); return; }
        var (result, message) = FileDestroyer.ScheduleRebootDelete(path);
        AppendLog(result == DeleteResult.ScheduledForReboot ? "info" : "err", message);
    }

    private void Probe_Click(object sender, RoutedEventArgs e)
    {
        var path = GetPath();
        if (string.IsNullOrEmpty(path)) { AppendLog("err", "Enter a path first"); return; }
        Task.Run(() =>
        {
            var r = FileDestroyer.UnlockFile(path);
            Dispatcher.Invoke(() =>
            {
                _lockers.Clear();
                foreach (var (pid, name) in r.LockingProcesses)
                    _lockers.Add(new LockerLine { Pid = pid, Name = name ?? "?" });
                LastOpTarget.Text = path;
                AppendLog("info", r.HandlesFound == 0
                    ? "probe → no open handles"
                    : $"probe → {r.HandlesFound} locking processes");
            });
        });
    }

    private void BuildDeleteTrace(DeleteResult result)
    {
        var green = (Brush)Application.Current.Resources["Green"];
        var red = (Brush)Application.Current.Resources["Accent2"];
        var dim = (Brush)Application.Current.Resources["Fg4"];
        var amber = (Brush)Application.Current.Resources["Amber"];
        _stages.Clear();
        _stages.Add(new TraceLine { Number = "01", Label = "DeleteFile() direct",
            Result = result == DeleteResult.Success ? "Success ✓" : "ERROR",
            StatusBrush = result == DeleteResult.Success ? green : red });
        _stages.Add(new TraceLine { Number = "02", Label = "Find handles → close foreign",
            Result = result == DeleteResult.Success ? "ok" : "—", StatusBrush = result == DeleteResult.Success ? green : dim });
        _stages.Add(new TraceLine { Number = "03", Label = "Rename → temp → DeleteFile()",
            Result = result == DeleteResult.Success ? "ok" : "—", StatusBrush = result == DeleteResult.Success ? green : dim });
        _stages.Add(new TraceLine { Number = "04", Label = "MoveFileEx(DELAY_UNTIL_REBOOT)",
            Result = result == DeleteResult.ScheduledForReboot ? "scheduled" : "skipped",
            StatusBrush = result == DeleteResult.ScheduledForReboot ? amber : dim });
    }
}
