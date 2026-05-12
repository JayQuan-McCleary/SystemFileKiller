using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using SystemFileKiller.Core;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using MessageBox = System.Windows.MessageBox;

namespace SystemFileKiller.GUI.Views;

public partial class NukeView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;

    private readonly ObservableCollection<FindingRow> _findings = new();
    private readonly ObservableCollection<OpRow> _ops = new();
    private readonly ObservableCollection<ConsoleLine> _console = new();

    public NukeView()
    {
        InitializeComponent();
        FindingsList.ItemsSource = _findings;
        OpsList.ItemsSource = _ops;
        ConsoleList.ItemsSource = _console;
        Append("info", "Nuke playbook ready — enter a target identifier above");
    }

    public sealed class FindingRow
    {
        public string Kind { get; init; } = "";
        public string Detail { get; init; } = "";
        public Brush KindBrush { get; init; } = System.Windows.Media.Brushes.Gray;
    }

    public sealed class OpRow
    {
        public string Index { get; init; } = "";
        public string Summary { get; init; } = "";
        public string Result { get; set; } = "";
        public Brush ResultBrush { get; set; } = System.Windows.Media.Brushes.Gray;
    }

    public sealed class ConsoleLine
    {
        public DateTime Timestamp { get; init; }
        public string Kind { get; init; } = "INFO ";
        public string Text { get; init; } = "";
        public Brush KindBrush { get; init; } = System.Windows.Media.Brushes.Gray;
    }

    private void Plan_Click(object sender, RoutedEventArgs e) => RunPlan(execute: false, dryRun: false);
    private void DryRun_Click(object sender, RoutedEventArgs e) => RunPlan(execute: true, dryRun: true);

    private void Execute_Click(object sender, RoutedEventArgs e)
    {
        var id = (IdentifierBox.Text ?? "").Trim();
        if (string.IsNullOrEmpty(id)) { OnAction?.Invoke("Nuke: identifier empty"); return; }
        var confirm = MessageBox.Show(
            $"Run destructive nuke for '{id}'?\n\nThis will kill processes, stop+delete services, " +
            $"disable+delete tasks, wipe install dirs, and strip persistence registry entries.",
            "Confirm nuke", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) { Append("warn", "execute cancelled by user"); return; }
        RunPlan(execute: true, dryRun: false);
    }

    private void RunPlan(bool execute, bool dryRun)
    {
        var id = (IdentifierBox.Text ?? "").Trim();
        if (string.IsNullOrEmpty(id))
        {
            Append("err", "identifier required");
            StatusBlock.Text = "no identifier provided";
            OnAction?.Invoke("Nuke: identifier required");
            return;
        }

        _findings.Clear();
        _ops.Clear();
        StatusBlock.Text = $"planning '{id}'...";
        Append("info", $"planning target: {id}");

        Task.Run(() =>
        {
            var plan = NukeOrchestrator.Plan(id);
            Dispatcher.Invoke(() => RenderPlan(plan, id));
            if (plan.Refused || plan.Ops.Length == 0 || !execute) return;

            var (_, resp) = NukeOrchestrator.Execute(id, dryRun);
            Dispatcher.Invoke(() => RenderResults(plan, resp, dryRun));
        });
    }

    private void RenderPlan(NukeTargetPlan plan, string id)
    {
        if (plan.Refused)
        {
            StatusBlock.Text = $"REFUSED: {plan.RefusedReason}";
            Append("err", $"refused: {plan.RefusedReason}");
            OnAction?.Invoke($"Nuke {id}: refused — {plan.RefusedReason}");
            return;
        }

        foreach (var f in plan.Findings)
        {
            _findings.Add(new FindingRow
            {
                Kind = f.Kind,
                Detail = f.Detail + (string.IsNullOrEmpty(f.Path) || f.Path == f.Detail ? "" : "  →  " + f.Path),
                KindBrush = KindBrushFor(f.Kind),
            });
        }

        for (int i = 0; i < plan.Ops.Length; i++)
        {
            _ops.Add(new OpRow
            {
                Index = $"[{i:00}]",
                Summary = $"{plan.Ops[i].Cmd}  {SummaryOf(plan.Ops[i])}",
            });
        }

        StatusBlock.Text = $"plan: {plan.Findings.Count} finding(s), {plan.Ops.Length} op(s)";
        Append("info", $"plan ready — {plan.Ops.Length} ops");
        OnAction?.Invoke($"Nuke {id}: {plan.Findings.Count} findings, {plan.Ops.Length} ops planned");
    }

    private void RenderResults(NukeTargetPlan plan, PipeResponse? resp, bool dryRun)
    {
        if (resp is null) { Append("warn", "no execution result returned"); return; }
        StatusBlock.Text = (dryRun ? "[DRY-RUN] " : "") + (resp.Result ?? "complete");
        Append(resp.Ok ? "ok" : "err", $"{(dryRun ? "DRYRUN " : "")}{resp.Result ?? ""}");
        if (resp.BatchResults is null) return;
        for (int i = 0; i < resp.BatchResults.Count && i < _ops.Count; i++)
        {
            var r = resp.BatchResults[i];
            _ops[i].Result = r.Ok ? "OK" : "FAIL";
            _ops[i].ResultBrush = r.Ok
                ? (Brush)Application.Current.Resources["Green"]
                : (Brush)Application.Current.Resources["Accent2"];
        }
        // Force refresh — ItemsControl doesn't observe per-item property changes without INPC.
        var items = OpsList.ItemsSource;
        OpsList.ItemsSource = null;
        OpsList.ItemsSource = items;
        OnAction?.Invoke($"Nuke executed: {resp.Result ?? ""}");
    }

    private static string SummaryOf(PipeRequest op) => op.Cmd switch
    {
        var c when !string.IsNullOrEmpty(op.Path) => op.Path!,
        var c when op.Pid.HasValue => $"pid={op.Pid}" + (op.KillTree ? " (tree)" : ""),
        var c when !string.IsNullOrEmpty(op.Name) => op.Name!,
        var c when !string.IsNullOrEmpty(op.Hive) => op.Hive + (op.ValueName is { Length: > 0 } ? "\\" + op.ValueName : ""),
        var c when op.Paths is { Length: > 0 } => $"{op.Paths.Length} paths",
        _ => ""
    };

    private static Brush KindBrushFor(string kind) => kind switch
    {
        "Process" => (Brush)Application.Current.Resources["Amber"],
        "Service" => (Brush)Application.Current.Resources["Violet"],
        "Task" => (Brush)Application.Current.Resources["Blue"],
        "UninstallStub" => (Brush)Application.Current.Resources["Fg3"],
        "FileOrDir" => (Brush)Application.Current.Resources["Fg2"],
        "RunKey" => (Brush)Application.Current.Resources["Amber"],
        _ => System.Windows.Media.Brushes.Gray,
    };

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
