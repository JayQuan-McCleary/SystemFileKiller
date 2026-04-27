using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using SystemFileKiller.Core;
using SystemFileKiller.GUI.Views;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using ColorConverter = System.Windows.Media.ColorConverter;

namespace SystemFileKiller.GUI;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _clock = new() { Interval = TimeSpan.FromSeconds(1) };
    private string _accent = "default";
    private string _surface = "dark";
    private string _density = "compact";

    public MainWindow()
    {
        App.Log("MainWindow ctor: before InitializeComponent");
        InitializeComponent();
        App.Log("MainWindow ctor: after InitializeComponent");

        Loaded += OnLoaded;
        _clock.Tick += (_, _) => UpdateClock();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        App.Log("MainWindow.OnLoaded: enter");
        try
        {
            // Force-restore in case the previous instance saved an iconic state.
            // (Windows can persist window placement per-class; if it was killed while
            // minimized, the next launch starts off-screen at -32000,-32000.)
            if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
            Activate();
            // Topmost flicker is the canonical way to force-foreground a WPF window
            // even when Windows would otherwise drop it behind the launcher.
            Topmost = true; Topmost = false;
            App.Log($"OnLoaded: window state forced (state={WindowState}, top={Top}, left={Left})");

            UpdateClock();
            _clock.Start();
            App.Log("OnLoaded: clock started");

            UpdatePrivilegePills();
            App.Log("OnLoaded: privilege pills updated");
        }
        catch (Exception ex)
        {
            App.Log($"!! OnLoaded threw early: {ex}");
            throw;
        }

        // Wire view callbacks: any user action bubbles up a status string.
        ViewProcesses.OnAction += SetStatus;
        ViewServices.OnAction += SetStatus;
        ViewFiles.OnAction += SetStatus;
        ViewRegistry.OnAction += SetStatus;
        ViewDashboard.OnAction += SetStatus;
        ViewAnalyze.OnAction += SetStatus;
        ViewDashboard.OnNavigate += SwitchScreen;
        ViewRegistry.OnSuspiciousCountChanged += UpdateRegistryBadge;

        // Hook the registry view's count update via a one-shot scan to populate the rail badge.
        ViewProcesses.OnCountsChanged += (visible, total) =>
            NavProcessesCount.Text = $"{visible}/{total}";
        ViewServices.OnCountsChanged += (visible, total) =>
            NavServicesCount.Text = $"{visible}/{total}";
        ViewRegistry.OnCountsChanged += (visible, total) =>
            NavRegistryCount.Text = $"{visible}/{total}";

        try
        {
            ApplyAccent(_accent);
            ApplySurface(_surface);
            ApplyDensity(_density);
            App.Log("OnLoaded: theme applied");

            // Default landing screen — Processes (matches the design's useState init)
            SwitchScreen("processes");
            App.Log("OnLoaded: switched to processes");

            OperatorLog.Append(OperatorLog.Kind.Info, "session started · operator JAY");
            App.Log("OnLoaded: complete");
        }
        catch (Exception ex)
        {
            App.Log($"!! OnLoaded threw late: {ex}");
            throw;
        }
    }

    // ── Title-bar window button handlers ──
    private void Min_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Max_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    // ── Clock ──
    private void UpdateClock()
    {
        var now = DateTime.UtcNow.ToString("HH:mm:ss");
        ClockText.Text = now;
        ClockText2.Text = now;
    }

    // ── Privilege pills ──
    private void UpdatePrivilegePills()
    {
        // Synchronous bits (cheap)
        bool admin = PrivilegeManager.IsElevated;
        DotAdmin.Fill = admin
            ? (Brush)Application.Current.Resources["Green"]
            : (Brush)Application.Current.Resources["Amber"];
        PillAdminText.Text = admin ? "ADMIN" : "USER";

        bool seDebug = PrivilegeManager.TryEnableDebugPrivilege();
        DotDebug.Fill = seDebug
            ? (Brush)Application.Current.Resources["Green"]
            : (Brush)Application.Current.Resources["Fg4"];

        // The pipe probe blocks on I/O — keep it OFF the UI thread so the window paints first.
        DotPipe.Fill = (Brush)Application.Current.Resources["Fg4"];
        PillPipeText.Text = "PIPE …";
        System.Threading.Tasks.Task.Run(() =>
        {
            bool pipe = PipeClient.IsServiceAvailable(300);
            Dispatcher.Invoke(() =>
            {
                DotPipe.Fill = pipe
                    ? (Brush)Application.Current.Resources["Green"]
                    : (Brush)Application.Current.Resources["Fg4"];
                PillPipeText.Text = pipe ? "PIPE \\\\.\\sfk" : "PIPE OFFLINE";
            });
        });
    }

    // ── Navigation ──
    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn) return;
        var key = btn.CommandParameter as string ?? "processes";
        SwitchScreen(key);
    }

    private void SetActiveNav(Button active)
    {
        foreach (var b in new[] { NavDashboard, NavProcesses, NavServices, NavFiles, NavRegistry, NavAnalyze })
            b.Tag = b == active ? "active" : null;
    }

    private Button NavButtonFor(string key) => key switch
    {
        "dashboard" => NavDashboard,
        "processes" => NavProcesses,
        "services"  => NavServices,
        "files"     => NavFiles,
        "registry"  => NavRegistry,
        "analyze"   => NavAnalyze,
        _ => NavProcesses,
    };

    private void SwitchScreen(string key)
    {
        ViewDashboard.Visibility = Visibility.Collapsed;
        ViewProcesses.Visibility = Visibility.Collapsed;
        ViewServices.Visibility = Visibility.Collapsed;
        ViewFiles.Visibility = Visibility.Collapsed;
        ViewRegistry.Visibility = Visibility.Collapsed;
        ViewAnalyze.Visibility = Visibility.Collapsed;

        switch (key)
        {
            case "dashboard":
                ViewDashboard.Visibility = Visibility.Visible;
                ViewDashboard.UpdateStats();
                ScreenLabel.Text = "OVERVIEW";
                break;
            case "processes":
                ViewProcesses.Visibility = Visibility.Visible;
                ViewProcesses.RefreshList();
                ScreenLabel.Text = "PROCESSES";
                break;
            case "services":
                ViewServices.Visibility = Visibility.Visible;
                ViewServices.RefreshList();
                ScreenLabel.Text = "SERVICES";
                break;
            case "files":
                ViewFiles.Visibility = Visibility.Visible;
                ScreenLabel.Text = "FILES";
                break;
            case "registry":
                ViewRegistry.Visibility = Visibility.Visible;
                ScreenLabel.Text = "REGISTRY";
                break;
            case "analyze":
                ViewAnalyze.Visibility = Visibility.Visible;
                ScreenLabel.Text = "ANALYZE";
                break;
        }

        SetActiveNav(NavButtonFor(key));
    }

    private void UpdateRegistryBadge(int suspicious)
    {
        if (suspicious > 0)
        {
            NavRegistryBadge.Visibility = Visibility.Visible;
            NavRegistryBadgeText.Text = suspicious.ToString();
        }
        else
        {
            NavRegistryBadge.Visibility = Visibility.Collapsed;
        }
    }

    // ── Status ──
    public void SetStatus(string text)
    {
        StatusText.Text = text;
        OperatorLog.Append(OperatorLog.Classify(text), text);
    }

    // ── Theme tray ──
    private void Accent_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button b && b.CommandParameter is string accent)
            ApplyAccent(accent);
    }

    private void Surface_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button b && b.CommandParameter is string surface)
            ApplySurface(surface);
    }

    private void Density_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button b && b.CommandParameter is string density)
            ApplyDensity(density);
    }

    private void ApplyAccent(string accent)
    {
        _accent = accent;
        // Override the Accent / Accent2 / AccentDim / AccentGlow brushes' Color value at runtime.
        // Each entry is (accent, accent2, dim, glow-with-alpha).
        (Color a, Color a2, Color dim, Color glow) = (accent, _surface) switch
        {
            ("amber",   "dark")  => (Hex("#E1B05E"), Hex("#F0C475"), Hex("#7A5B22"), HexA("#E1B05E", 0x2E)),
            ("blue",    "dark")  => (Hex("#5BA3DD"), Hex("#7BBDED"), Hex("#1E4A75"), HexA("#5BA3DD", 0x2E)),
            ("green",   "dark")  => (Hex("#5BD68D"), Hex("#7DE5A8"), Hex("#1E5A35"), HexA("#5BD68D", 0x2E)),
            ("amber",   "paper") => (Hex("#A37828"), Hex("#7E5A1A"), Hex("#553B0E"), HexA("#A37828", 0x2E)),
            ("blue",    "paper") => (Hex("#264FA8"), Hex("#1A3D8A"), Hex("#0F2860"), HexA("#264FA8", 0x2E)),
            ("green",   "paper") => (Hex("#2A864E"), Hex("#1F6A3D"), Hex("#13442A"), HexA("#2A864E", 0x2E)),
            (_,         "paper") => (Hex("#A12A1F"), Hex("#7C1F17"), Hex("#5A1610"), HexA("#A12A1F", 0x2E)),
            _                    => (Hex("#DA4339"), Hex("#FA5C4D"), Hex("#7C2A23"), HexA("#DA4339", 0x2E)),
        };

        SetBrush("Accent", a);
        SetBrush("Accent2", a2);
        SetBrush("AccentDim", dim);
        SetBrush("AccentGlow", glow);

        // Mark active swatch with a Tag (used by the TrayBtn template to draw a focus ring)
        SwatchRed.Tag   = accent == "default" ? "active" : null;
        SwatchAmber.Tag = accent == "amber"   ? "active" : null;
        SwatchBlue.Tag  = accent == "blue"    ? "active" : null;
        SwatchGreen.Tag = accent == "green"   ? "active" : null;
    }

    private void ApplySurface(string surface)
    {
        _surface = surface;
        if (surface == "paper")
        {
            SetBrush("Bg",        Hex("#F6F3EC"));
            SetBrush("Bg2",       Hex("#FFFFFF"));
            SetBrush("Panel",     Hex("#FFFFFF"));
            SetBrush("Panel2",    Hex("#F0ECE2"));
            SetBrush("Line",      Hex("#D8D2C2"));
            SetBrush("Line2",     Hex("#B6AE9A"));
            SetBrush("Fg",        Hex("#0D0C0A"));
            SetBrush("Fg2",       Hex("#2A2722"));
            SetBrush("Fg3",       Hex("#4A4640"));
            SetBrush("Fg4",       Hex("#6E695E"));
            SetBrush("Green",     Hex("#2A6B4D"));
            SetBrush("Amber",     Hex("#9E5F1A"));
            SetBrush("Blue",      Hex("#1F4FA5"));
            SetBrush("Violet",    Hex("#6B3CA8"));
            SetBrush("TitleBg",   Hex("#1A1814"));
            SetBrush("RailBg",    Hex("#EBE6D8"));
            SetBrush("ConsoleBg", Hex("#14110D"));
            SetBrush("SelectedRowBg", Hex("#F0D4CC"));
        }
        else
        {
            SetBrush("Bg",        Hex("#0A0C10"));
            SetBrush("Bg2",       Hex("#0E1116"));
            SetBrush("Panel",     Hex("#13161C"));
            SetBrush("Panel2",    Hex("#181C24"));
            SetBrush("Line",      Hex("#232934"));
            SetBrush("Line2",     Hex("#2C3340"));
            SetBrush("Fg",        Hex("#E6E9EF"));
            SetBrush("Fg2",       Hex("#B6BCC8"));
            SetBrush("Fg3",       Hex("#7D8492"));
            SetBrush("Fg4",       Hex("#535A68"));
            SetBrush("Green",     Hex("#5DD2A1"));
            SetBrush("Amber",     Hex("#EAB95C"));
            SetBrush("Blue",      Hex("#6FAEDA"));
            SetBrush("Violet",    Hex("#A88AD9"));
            SetBrush("TitleBg",   Hex("#07090D"));
            SetBrush("RailBg",    Hex("#07090D"));
            SetBrush("ConsoleBg", Hex("#04060A"));
            SetBrush("SelectedRowBg", HexA("#332014", 0x8C));
        }

        // Re-apply accent so paper-tuned shades pick up
        ApplyAccent(_accent);
    }

    private void ApplyDensity(string density)
    {
        _density = density;
        // The DataGrid styles in App.xaml use RowHeight="28". For "cozy" we bump to 36.
        var rowHeight = density == "cozy" ? 36.0 : 28.0;
        // Update all DataGrid instances at runtime by walking the visual tree
        SetDataGridRowHeight(this, rowHeight);

        DensityCompact.Tag = density == "compact" ? "active" : null;
        DensityCozy.Tag    = density == "cozy"    ? "active" : null;

        SwatchDark.Tag  = _surface == "dark"  ? "active" : null;
        SwatchPaper.Tag = _surface == "paper" ? "active" : null;
    }

    private static void SetDataGridRowHeight(DependencyObject root, double h)
    {
        if (root is DataGrid dg) dg.RowHeight = h;
        int n = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < n; i++) SetDataGridRowHeight(VisualTreeHelper.GetChild(root, i), h);
    }

    private static void SetBrush(string key, Color c)
    {
        // Always replace the resource entry: brushes declared in App.xaml are
        // auto-frozen and can't have their .Color mutated. DynamicResource
        // consumers re-resolve when the keyed resource changes.
        Application.Current.Resources[key] = new SolidColorBrush(c);
    }

    private static Color Hex(string hex)
    {
        var c = (Color)ColorConverter.ConvertFromString(hex)!;
        return c;
    }
    private static Color HexA(string hex, byte a)
    {
        var c = Hex(hex);
        return Color.FromArgb(a, c.R, c.G, c.B);
    }
}
