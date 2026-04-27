using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Threading;
using MessageBox = System.Windows.MessageBox;

namespace SystemFileKiller.GUI;

public partial class App : System.Windows.Application
{
    private static readonly string LogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SystemFileKiller", "startup.log");

    protected override void OnStartup(StartupEventArgs e)
    {
        try { Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!); } catch { }

        Log($"=== App.OnStartup · {DateTime.Now:yyyy-MM-dd HH:mm:ss} · admin={IsRunningAsAdmin()} · pid={Environment.ProcessId} ===");

        // Catch any unhandled exception on the UI thread and write it to disk.
        DispatcherUnhandledException += (_, args) =>
        {
            Log($"!! DispatcherUnhandledException: {args.Exception}");
            args.Handled = false; // let it crash naturally
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            Log($"!! AppDomain.UnhandledException: {args.ExceptionObject}");
        };

        try
        {
            base.OnStartup(e);
            Log("base.OnStartup returned normally");
        }
        catch (Exception ex)
        {
            Log($"!! base.OnStartup threw: {ex}");
            throw;
        }

        // No in-app admin prompt. The title-bar pill shows ADMIN / USER — if you want
        // to elevate, right-click the exe → "Run as administrator". Avoids the
        // double-dialog UX trap (in-app YES → UAC YES, with an off-screen UAC failure mode).
    }

    /// <summary>
    /// Helper if a user ever wants to relaunch elevated from inside the app.
    /// Currently unused — wire to a UI button/menu item when needed.
    /// </summary>
    public static bool TryRelaunchElevated()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (exe == null) return false;
            Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,
                Verb = "runas"
            });
            Current.Shutdown();
            return true;
        }
        catch { return false; }
    }

    public static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void Log(string line)
    {
        try { File.AppendAllText(LogPath, $"{DateTime.Now:HH:mm:ss.fff} {line}{Environment.NewLine}"); }
        catch { /* swallow */ }
    }
}
