using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using SystemFileKiller.Core;
using MessageBox = System.Windows.MessageBox;

namespace SystemFileKiller.GUI.Views;

public partial class TasksView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;

    private readonly ObservableCollection<TaskRow> _rows = new();

    public TasksView()
    {
        InitializeComponent();
        TasksGrid.ItemsSource = _rows;
        TasksGrid.SelectionChanged += (_, _) => UpdateDetail();
        Loaded += (_, _) => Refresh_Click(this, new RoutedEventArgs());
    }

    public sealed class TaskRow
    {
        public string SuspMarker => IsSuspicious ? "!" : "";
        public string Status { get; init; } = "";
        public string TaskPath { get; init; } = "";
        public string TaskName { get; init; } = "";
        public string Author { get; init; } = "";
        public string TaskRun { get; init; } = "";
        public string LastRunTime { get; init; } = "";
        public string LastResult { get; init; } = "";
        public string NextRunTime { get; init; } = "";
        public bool IsSuspicious { get; init; }
        public string? SuspicionReason { get; init; }
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        var suspOnly = SuspiciousOnly.IsChecked == true;
        CountLabel.Text = "loading…";
        Task.Run(() =>
        {
            var tasks = TaskManager.ListTasks(suspOnly);
            Dispatcher.Invoke(() =>
            {
                _rows.Clear();
                foreach (var t in tasks)
                {
                    _rows.Add(new TaskRow
                    {
                        Status = t.Status,
                        TaskPath = t.TaskPath,
                        TaskName = t.TaskName,
                        Author = t.Author,
                        TaskRun = t.TaskRun,
                        LastRunTime = t.LastRunTime,
                        LastResult = t.LastResult,
                        NextRunTime = t.NextRunTime,
                        IsSuspicious = t.IsSuspicious,
                        SuspicionReason = t.SuspicionReason,
                    });
                }
                int sus = _rows.Count(r => r.IsSuspicious);
                CountLabel.Text = $"{_rows.Count} task(s){(sus > 0 ? $" · {sus} suspicious" : "")}";
                OnAction?.Invoke($"Tasks loaded: {_rows.Count}, {sus} suspicious");
            });
        });
    }

    private void UpdateDetail()
    {
        if (TasksGrid.SelectedItem is not TaskRow r)
        {
            DetailPath.Text = DetailTaskRun.Text = DetailSusp.Text = DetailLastRun.Text =
                DetailLastResult.Text = DetailNextRun.Text = "—";
            return;
        }
        DetailPath.Text = r.TaskPath;
        DetailTaskRun.Text = string.IsNullOrEmpty(r.TaskRun) ? "(none)" : r.TaskRun;
        DetailSusp.Text = r.IsSuspicious ? r.SuspicionReason ?? "(flagged)" : "(not flagged)";
        DetailLastRun.Text = r.LastRunTime;
        DetailLastResult.Text = r.LastResult;
        DetailNextRun.Text = r.NextRunTime;
    }

    private void Disable_Click(object sender, RoutedEventArgs e) => RunOnSelected(TaskManager.DisableTask, "disable");
    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        var sel = TasksGrid.SelectedItems.Cast<TaskRow>().ToList();
        if (sel.Count == 0) return;
        var ok = MessageBox.Show($"Permanently delete {sel.Count} scheduled task(s)?",
            "Confirm delete", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (ok != MessageBoxResult.Yes) return;
        RunOnSelected(TaskManager.DeleteTask, "delete");
    }

    private void RunOnSelected(Func<string, ServiceOpResult> action, string verb)
    {
        var sel = TasksGrid.SelectedItems.Cast<TaskRow>().ToList();
        if (sel.Count == 0) { OnAction?.Invoke($"Tasks: select rows first"); return; }
        Task.Run(() =>
        {
            int ok = 0;
            foreach (var r in sel)
            {
                if (action(r.TaskPath) is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState) ok++;
            }
            Dispatcher.Invoke(() =>
            {
                OnAction?.Invoke($"Tasks {verb}: {ok}/{sel.Count} ok");
                Refresh_Click(this, new RoutedEventArgs());
            });
        });
    }
}
