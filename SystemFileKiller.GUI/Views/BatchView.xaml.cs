using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SystemFileKiller.Core;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using Button = System.Windows.Controls.Button;
using ListBox = System.Windows.Controls.ListBox;

namespace SystemFileKiller.GUI.Views;

public partial class BatchView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;

    private readonly ObservableCollection<QueueItem> _queue = new();
    private readonly ObservableCollection<ConsoleLine> _console = new();

    public BatchView()
    {
        InitializeComponent();
        QueueList.ItemsSource = _queue;
        ConsoleList.ItemsSource = _console;
        Append("info", "Batch builder ready — pick ops from the palette to queue them");
    }

    public sealed class ConsoleLine
    {
        public DateTime Timestamp { get; init; }
        public string Kind { get; init; } = "INFO ";
        public string Text { get; init; } = "";
        public Brush KindBrush { get; init; } = System.Windows.Media.Brushes.Gray;
    }

    public sealed class QueueItem : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;
        private void Set<T>(ref T field, T value, [CallerMemberName] string? prop = null)
        {
            if (Equals(field, value)) return;
            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
        }

        public string Cmd { get; init; } = "";
        public string IndexLabel { get; set; } = "";
        public Brush CmdBrush { get; init; } = System.Windows.Media.Brushes.Gray;

        // Editable params, encoded as semicolon-separated key=value pairs.
        // Kept simple — flexible across all op types without per-op UI complexity.
        private string _params = "";
        public string Params { get => _params; set => Set(ref _params, value); }

        private string _result = "";
        public string Result { get => _result; set => Set(ref _result, value); }

        private Brush _resultBrush = System.Windows.Media.Brushes.Gray;
        public Brush ResultBrush { get => _resultBrush; set => Set(ref _resultBrush, value); }
    }

    private void AddOp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string cmd) return;
        var stub = DefaultParamsFor(cmd);
        var item = new QueueItem
        {
            Cmd = cmd,
            CmdBrush = BrushForCmd(cmd),
            Params = stub,
        };
        _queue.Add(item);
        ReindexQueue();
        QueueList.SelectedItem = item;
        Append("info", $"queued [{_queue.Count - 1:00}] {cmd}");
        OnAction?.Invoke($"Batch: queued {cmd} (depth={_queue.Count})");
    }

    private static string DefaultParamsFor(string cmd) => cmd switch
    {
        "kill_process" => "pid=0; killTree=false",
        "kill_process_by_name" => "name=; killTree=false",
        "stop_service" or "disable_service" or "delete_service" => "name=",
        "delete_file" or "delete_dir" or "quarantine_file" => "path=",
        "task_disable" or "task_delete" => "name=",
        "registry_remove_key" => "hive=HKLM\\SOFTWARE\\",
        "registry_remove_value" => "hive=HKLM\\SOFTWARE\\; valueName=",
        "hosts_remove_pattern" => "pattern=",
        "restore_point_create" => "description=SFK checkpoint",
        _ => "",
    };

    private static Brush BrushForCmd(string cmd) => cmd switch
    {
        var c when c.StartsWith("kill") => (Brush)Application.Current.Resources["Amber"],
        var c when c.Contains("service") => (Brush)Application.Current.Resources["Violet"],
        var c when c.Contains("delete") || c.Contains("quarantine") => (Brush)Application.Current.Resources["Accent2"],
        var c when c.StartsWith("task") => (Brush)Application.Current.Resources["Blue"],
        var c when c.StartsWith("registry") => (Brush)Application.Current.Resources["Fg2"],
        _ => (Brush)Application.Current.Resources["Fg3"],
    };

    private void ReindexQueue()
    {
        for (int i = 0; i < _queue.Count; i++)
            _queue[i].IndexLabel = $"[{i:00}]";
    }

    private void MoveUp_Click(object sender, RoutedEventArgs e)
    {
        var idx = QueueList.SelectedIndex;
        if (idx <= 0) return;
        (_queue[idx], _queue[idx - 1]) = (_queue[idx - 1], _queue[idx]);
        ReindexQueue();
        QueueList.SelectedIndex = idx - 1;
    }

    private void MoveDown_Click(object sender, RoutedEventArgs e)
    {
        var idx = QueueList.SelectedIndex;
        if (idx < 0 || idx >= _queue.Count - 1) return;
        (_queue[idx], _queue[idx + 1]) = (_queue[idx + 1], _queue[idx]);
        ReindexQueue();
        QueueList.SelectedIndex = idx + 1;
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        var idx = QueueList.SelectedIndex;
        if (idx < 0) return;
        _queue.RemoveAt(idx);
        ReindexQueue();
        if (_queue.Count > 0) QueueList.SelectedIndex = Math.Min(idx, _queue.Count - 1);
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        _queue.Clear();
        Append("info", "queue cleared");
    }

    private void Run_Click(object sender, RoutedEventArgs e)
    {
        if (_queue.Count == 0) { Append("warn", "queue is empty"); return; }

        bool dry = DryRunCheck.IsChecked == true;
        bool stopOnError = StopOnErrorCheck.IsChecked == true;

        // Reset visual state
        foreach (var q in _queue) { q.Result = ""; q.ResultBrush = System.Windows.Media.Brushes.Gray; }

        // Build pipe ops from queue items
        PipeRequest[] ops;
        try
        {
            ops = _queue.Select(BuildOp).ToArray();
        }
        catch (Exception ex)
        {
            Append("err", $"failed to parse queue: {ex.Message}");
            return;
        }

        var batch = new PipeRequest
        {
            Cmd = PipeProtocol.Commands.Batch,
            Ops = ops,
            DryRun = dry,
            StopOnError = stopOnError,
        };

        Append("info", $"dispatching {ops.Length} op(s){(dry ? " [dry-run]" : "")}{(stopOnError ? " [stop-on-error]" : "")}");
        OnAction?.Invoke($"Batch: running {ops.Length} ops{(dry ? " (dry)" : "")}");

        Task.Run(() =>
        {
            var resp = PipeClient.Send(batch, timeoutMs: 30 * 60 * 1000);
            Dispatcher.Invoke(() => RenderResults(resp, dry));
        });
    }

    private void RenderResults(PipeResponse resp, bool dry)
    {
        Append(resp.Ok ? "ok" : "err", $"{(dry ? "DRYRUN " : "")}{resp.Result ?? "(no summary)"}");
        if (resp.BatchResults is null) return;
        for (int i = 0; i < resp.BatchResults.Count && i < _queue.Count; i++)
        {
            var r = resp.BatchResults[i];
            _queue[i].Result = r.Ok ? "OK" : "FAIL";
            _queue[i].ResultBrush = r.Ok
                ? (Brush)Application.Current.Resources["Green"]
                : (Brush)Application.Current.Resources["Accent2"];
            if (!r.Ok && !string.IsNullOrEmpty(r.Error))
                Append("err", $"[{i:00}] {r.Error}");
        }
    }

    private static PipeRequest BuildOp(QueueItem q)
    {
        var req = new PipeRequest { Cmd = q.Cmd };
        foreach (var pair in (q.Params ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = pair.Split('=', 2, StringSplitOptions.None);
            if (kv.Length != 2) continue;
            var key = kv[0].Trim();
            var val = kv[1].Trim();
            switch (key.ToLowerInvariant())
            {
                case "pid": if (int.TryParse(val, out var p)) req.Pid = p; break;
                case "killtree": req.KillTree = val.Equals("true", StringComparison.OrdinalIgnoreCase); break;
                case "name": req.Name = val; break;
                case "path": req.Path = val; break;
                case "paths": req.Paths = val.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToArray(); break;
                case "hive": req.Hive = val; break;
                case "valuename": req.ValueName = val; break;
                case "valuedata": req.ValueData = val; break;
                case "valuekind": req.ValueKind = val; break;
                case "quarantineid": req.QuarantineId = val; break;
                case "olderthandays": if (int.TryParse(val, out var d)) req.OlderThanDays = d; break;
                case "pattern": req.Pattern = val; break;
                case "description": req.Description = val; break;
            }
        }
        return req;
    }

    private void Append(string kind, string text)
    {
        var brush = kind switch
        {
            "ok" => (Brush)Application.Current.Resources["Green"],
            "err" => (Brush)Application.Current.Resources["Accent2"],
            "warn" => (Brush)Application.Current.Resources["Amber"],
            _ => (Brush)Application.Current.Resources["Blue"],
        };
        _console.Add(new ConsoleLine
        {
            Timestamp = DateTime.Now,
            Kind = $" {kind.ToUpperInvariant(),-4} ",
            Text = text,
            KindBrush = brush,
        });
    }
}
