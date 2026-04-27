using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SystemFileKiller.Core;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using SolidColorBrush = System.Windows.Media.SolidColorBrush;
using MessageBox = System.Windows.MessageBox;

namespace SystemFileKiller.GUI.Views;

public partial class AnalyzeView : System.Windows.Controls.UserControl
{
    public event Action<string>? OnAction;

    private string? _currentPath;
    private List<HeuristicRow> _heuristics = new();

    public AnalyzeView()
    {
        InitializeComponent();
        HeuristicsList.ItemsSource = _heuristics;
    }

    public sealed class HeuristicRow
    {
        public string Check { get; init; } = "";
        public string Result { get; init; } = "";
        public Brush Brush { get; init; } = System.Windows.Media.Brushes.Gray;
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Executables (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All Files|*.*"
        };
        if (dlg.ShowDialog() == true)
        {
            _currentPath = dlg.FileName;
            Analyze();
        }
    }

    private void Reanalyze_Click(object sender, RoutedEventArgs e)
    {
        if (_currentPath != null) Analyze();
        else OnAction?.Invoke("analyze · open a file first");
    }

    public void AnalyzeFile(string path)
    {
        _currentPath = path;
        Analyze();
    }

    private void Analyze()
    {
        if (string.IsNullOrEmpty(_currentPath) || !File.Exists(_currentPath))
        {
            MessageBox.Show("File not found.", "Analyze", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SubjectPath.Text = _currentPath;
        OnAction?.Invoke($"analyze → {Path.GetFileName(_currentPath)}");
        OperatorLog.Append(OperatorLog.Kind.Info, $"analyze · {Path.GetFileName(_currentPath)}");

        var path = _currentPath;
        Task.Run(() =>
        {
            try
            {
                var fi = new FileInfo(path);
                string sha256, md5;
                using (var s = File.OpenRead(path))
                using (var hasher = SHA256.Create()) sha256 = Convert.ToHexStringLower(hasher.ComputeHash(s));
                using (var s = File.OpenRead(path))
                using (var hasher = MD5.Create()) md5 = Convert.ToHexStringLower(hasher.ComputeHash(s));

                bool signed = false;
                string? signer = null, issuer = null;
                try
                {
#pragma warning disable SYSLIB0057
                    var cert = X509Certificate2.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                    signer = cert.Subject;
                    issuer = cert.Issuer;
                    signed = true;
                    cert.Dispose();
                }
                catch { /* unsigned */ }

                var ver = FileVersionInfo.GetVersionInfo(path);

                byte[] head = new byte[Math.Min(256, fi.Length)];
                using (var s = File.OpenRead(path)) s.ReadExactly(head);

                Dispatcher.Invoke(() =>
                {
                    PopulateIdentity(fi, sha256, md5);
                    PopulateSignature(signed, signer, issuer, ver);
                    PopulateBadges(path, signed);
                    PopulateHeuristics(path, signed, ver, fi);
                    HexPreview.Text = FormatHex(head);
                    PopulatePlaybook(path, signed);

                    OperatorLog.Append(signed ? OperatorLog.Kind.Ok : OperatorLog.Kind.Warn,
                        $"analyze → {Path.GetFileName(path)} · sig={(signed ? "ok" : "unsigned")}");
                });
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show($"Analyze failed: {ex.Message}", "Analyze", MessageBoxButton.OK, MessageBoxImage.Error);
                    OperatorLog.Append(OperatorLog.Kind.Err, $"analyze fail · {ex.Message}");
                });
            }
        });
    }

    private void PopulateIdentity(FileInfo fi, string sha, string md5)
    {
        DetSize.Text = $"{fi.Length:N0} bytes ({fi.Length / 1024.0:F1} KB)";
        DetSha.Text = sha;
        DetMd5.Text = md5;
        DetCreated.Text = fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss");
        DetModified.Text = fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");
    }

    private void PopulateSignature(bool signed, string? signer, string? issuer, FileVersionInfo ver)
    {
        if (signed)
        {
            DetSigned.Text = "● Yes — Authenticode signature present";
            DetSigned.Foreground = (Brush)Application.Current.Resources["Green"];
            DetSigner.Text = signer ?? "—";
        }
        else
        {
            DetSigned.Text = "● No — image is not Authenticode-signed";
            DetSigned.Foreground = (Brush)Application.Current.Resources["Accent2"];
            DetSigner.Text = "—";
        }
        DetProduct.Text = ver.ProductName ?? "—";
        DetVersion.Text = ver.ProductVersion ?? ver.FileVersion ?? "—";
        DetDescription.Text = ver.FileDescription ?? "—";
    }

    private void PopulateBadges(string path, bool signed)
    {
        BadgeRow.Children.Clear();
        BadgeRow.Children.Add(MakeBadge(signed ? "SIGNED" : "UNSIGNED", signed ? "green" : "accent"));

        if (path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\AppData\\Local\\Temp", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\AppData\\Roaming\\Temp", StringComparison.OrdinalIgnoreCase))
            BadgeRow.Children.Add(MakeBadge("USER-TEMP", "amber"));
        if (path.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase))
            BadgeRow.Children.Add(MakeBadge("DOWNLOADS", "amber"));
        if (path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase))
            BadgeRow.Children.Add(MakeBadge("SYSTEM-DIR", "blue"));
    }

    private FrameworkElement MakeBadge(string text, string tone)
    {
        var bg = tone switch
        {
            "green" => "AccentGlow",
            "amber" => "AccentGlow",
            "blue" => "AccentGlow",
            _ => "AccentGlow"
        };
        var border = (Brush)Application.Current.Resources[
            tone switch { "green" => "Green", "amber" => "Amber", "blue" => "Blue", _ => "Accent" }];
        var fg = (Brush)Application.Current.Resources[
            tone switch { "green" => "Green", "amber" => "Amber", "blue" => "Blue", _ => "Accent2" }];
        var glowColor = ((SolidColorBrush)border).Color;
        var bgBrush = new SolidColorBrush(System.Windows.Media.Color.FromArgb(0x2E, glowColor.R, glowColor.G, glowColor.B));

        var b = new System.Windows.Controls.Border
        {
            Background = bgBrush,
            BorderBrush = border,
            BorderThickness = new System.Windows.Thickness(1),
            CornerRadius = new System.Windows.CornerRadius(2),
            Padding = new System.Windows.Thickness(5, 1, 5, 1),
            Margin = new System.Windows.Thickness(0, 0, 6, 0),
            VerticalAlignment = System.Windows.VerticalAlignment.Center,
            Child = new TextBlock
            {
                Text = text,
                FontFamily = (System.Windows.Media.FontFamily)Application.Current.Resources["FontMono"],
                FontSize = 10,
                Foreground = fg
            }
        };
        return b;
    }

    private void PopulateHeuristics(string path, bool signed, FileVersionInfo ver, FileInfo fi)
    {
        var rows = new List<HeuristicRow>();
        var green = (Brush)Application.Current.Resources["Green"];
        var amber = (Brush)Application.Current.Resources["Amber"];
        var red = (Brush)Application.Current.Resources["Accent2"];
        var dim = (Brush)Application.Current.Resources["Fg4"];

        rows.Add(new HeuristicRow
        {
            Check = "Authenticode signature",
            Result = signed ? "present" : "absent",
            Brush = signed ? green : red
        });
        var dir = Path.GetDirectoryName(path) ?? "";
        bool tempDir = dir.Contains("\\Temp", StringComparison.OrdinalIgnoreCase) || dir.Contains("\\AppData", StringComparison.OrdinalIgnoreCase);
        rows.Add(new HeuristicRow
        {
            Check = "Location",
            Result = tempDir ? $"user-writable ({Path.GetFileName(dir)})" : "system / program path",
            Brush = tempDir ? amber : green
        });
        bool hasVer = !string.IsNullOrWhiteSpace(ver.ProductName) || !string.IsNullOrWhiteSpace(ver.CompanyName);
        rows.Add(new HeuristicRow
        {
            Check = "Version metadata",
            Result = hasVer ? $"{ver.CompanyName ?? "?"} · {ver.ProductName ?? "?"}" : "stripped or missing",
            Brush = hasVer ? green : amber
        });
        var age = DateTime.Now - fi.LastWriteTime;
        rows.Add(new HeuristicRow
        {
            Check = "Last modified",
            Result = age.TotalDays < 7
                ? $"{(int)age.TotalDays}d ago — recent"
                : $"{(int)age.TotalDays}d ago",
            Brush = age.TotalDays < 7 ? amber : dim
        });
        bool tinyExe = fi.Length < 8 * 1024 && Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase);
        if (tinyExe)
            rows.Add(new HeuristicRow
            {
                Check = "Size sanity",
                Result = $"{fi.Length} bytes — atypical for exe",
                Brush = amber
            });

        _heuristics.Clear();
        foreach (var r in rows) _heuristics.Add(r);
        HeuristicsList.ItemsSource = null;
        HeuristicsList.ItemsSource = _heuristics;
    }

    private static string FormatHex(byte[] data)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += 16)
        {
            sb.Append($"{i:X8}  ");
            for (int j = 0; j < 16; j++)
            {
                if (i + j < data.Length) sb.Append($"{data[i + j]:X2} ");
                else sb.Append("   ");
            }
            sb.Append(" ");
            for (int j = 0; j < 16 && i + j < data.Length; j++)
            {
                byte b = data[i + j];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private void PopulatePlaybook(string path, bool signed)
    {
        var sb = new StringBuilder();
        if (signed)
        {
            sb.AppendLine("Binary is Authenticode-signed. No immediate action recommended.");
            sb.AppendLine();
            sb.AppendLine("If you still suspect this file:");
            sb.AppendLine("  1. Verify the signer chain in the Signature panel.");
            sb.AppendLine("  2. Cross-check the SHA-256 against external sources.");
            sb.AppendLine("  3. Submit to a multi-engine scanner manually.");
        }
        else
        {
            sb.AppendLine("Binary is not signed. Recommended playbook:");
            sb.AppendLine();
            sb.AppendLine($"  1. Find loaded process from path → use Processes screen, filter '{Path.GetFileName(path)}'.");
            sb.AppendLine("  2. Force-kill via the escalation ladder (sfk_process_kill).");
            sb.AppendLine($"  3. Force-delete the image: {path}");
            sb.AppendLine("  4. Run Registry → Show suspicious only. Purge any persistence entry referencing this image.");
            if (path.Contains("\\Temp", StringComparison.OrdinalIgnoreCase))
                sb.AppendLine("  5. Sweep the parent temp directory for related droppers (Files → Wipe directory).");
        }
        PlaybookText.Text = sb.ToString().TrimEnd();
    }
}
