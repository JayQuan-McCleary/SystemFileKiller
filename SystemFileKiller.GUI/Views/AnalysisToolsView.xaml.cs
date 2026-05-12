using System;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using SystemFileKiller.Core;

namespace SystemFileKiller.GUI.Views;

public partial class AnalysisToolsView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;

    public AnalysisToolsView() => InitializeComponent();

    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { CheckFileExists = true };
        if (dlg.ShowDialog() == true) FilePathBox.Text = dlg.FileName;
    }

    private void Hash_Click(object sender, RoutedEventArgs e)
    {
        var p = (FilePathBox.Text ?? "").Trim();
        if (string.IsNullOrEmpty(p)) { OnAction?.Invoke("Hash: path required"); return; }
        HashOut.Text = "computing…";
        Task.Run(() =>
        {
            var h = HashUtil.ComputeHash(p);
            Dispatcher.Invoke(() =>
            {
                if (h is null) { HashOut.Text = "file not found"; return; }
                HashOut.Text =
                    $"size:    {h.SizeBytes:N0} bytes\n" +
                    $"sha256:  {h.Sha256}\n" +
                    $"md5:     {h.Md5}";
                OnAction?.Invoke($"Hash computed for {p}");
            });
        });
    }

    private void Sig_Click(object sender, RoutedEventArgs e)
    {
        var p = (FilePathBox.Text ?? "").Trim();
        if (string.IsNullOrEmpty(p)) { OnAction?.Invoke("Signature: path required"); return; }
        SigOut.Text = "verifying…";
        Task.Run(() =>
        {
            var s = HashUtil.VerifySignature(p);
            Dispatcher.Invoke(() =>
            {
                var sb = new StringBuilder();
                sb.AppendLine($"status:    {s.Status}");
                sb.AppendLine($"subject:   {s.Subject ?? "(none)"}");
                sb.AppendLine($"issuer:    {s.Issuer ?? "(none)"}");
                sb.AppendLine($"notBefore: {s.NotBefore:yyyy-MM-dd}");
                sb.AppendLine($"notAfter:  {s.NotAfter:yyyy-MM-dd}");
                sb.AppendLine($"thumb:     {s.Thumbprint ?? "(none)"}");
                if (!string.IsNullOrEmpty(s.Detail)) sb.AppendLine($"detail:    {s.Detail}");
                SigOut.Text = sb.ToString();
                OnAction?.Invoke($"Signature: {s.Status}");
            });
        });
    }

    private void Tree_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse((PidBox.Text ?? "").Trim(), out var pid)) { OnAction?.Invoke("Tree: numeric PID required"); return; }
        TreeOut.Text = "scanning WMI…";
        Task.Run(() =>
        {
            var tree = ProcessTreeUtil.GetTree(pid);
            Dispatcher.Invoke(() =>
            {
                if (tree is null) { TreeOut.Text = $"PID {pid} not found"; return; }
                var sb = new StringBuilder();
                Render(tree, 0, sb);
                TreeOut.Text = sb.ToString();
                OnAction?.Invoke($"Tree for PID {pid}: rendered");
            });
        });

        static void Render(ProcessNode n, int depth, StringBuilder sb)
        {
            sb.Append(new string(' ', depth * 2));
            sb.Append(depth > 0 ? "└─ " : "");
            sb.AppendLine($"[{n.Pid,5}] {n.Name}  {n.MemoryMB,6}MB  {n.Path ?? ""}");
            foreach (var c in n.Children) Render(c, depth + 1, sb);
        }
    }

    private void Anc_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse((PidBox.Text ?? "").Trim(), out var pid)) { OnAction?.Invoke("Ancestry: numeric PID required"); return; }
        TreeOut.Text = "walking parents…";
        Task.Run(() =>
        {
            var chain = ProcessTreeUtil.GetAncestry(pid);
            Dispatcher.Invoke(() =>
            {
                if (chain.Count == 0) { TreeOut.Text = $"PID {pid} not found"; return; }
                var sb = new StringBuilder();
                for (int i = 0; i < chain.Count; i++)
                {
                    var indent = new string(' ', i * 2);
                    sb.AppendLine($"{indent}{(i == 0 ? "" : "↑ ")}[{chain[i].Pid,5}] {chain[i].Name}  {chain[i].Path ?? ""}");
                }
                TreeOut.Text = sb.ToString();
                OnAction?.Invoke($"Ancestry for PID {pid}: {chain.Count} ancestors");
            });
        });
    }
}
