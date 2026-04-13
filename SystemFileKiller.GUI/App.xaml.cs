using System.Diagnostics;
using System.Security.Principal;
using System.Windows;

namespace SystemFileKiller.GUI;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (!IsRunningAsAdmin())
        {
            var result = System.Windows.MessageBox.Show(
                "System File Killer works best when running as Administrator.\n\n" +
                "Without admin privileges, some features (force-killing protected processes, " +
                "unlocking system file handles, modifying HKLM registry keys) will not work.\n\n" +
                "Restart as Administrator?",
                "Elevation Recommended",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    var exePath = Environment.ProcessPath;
                    if (exePath != null)
                    {
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = exePath,
                            UseShellExecute = true,
                            Verb = "runas"
                        };
                        Process.Start(startInfo);
                    }
                }
                catch
                {
                    // User declined UAC or something went wrong - continue without admin
                    return;
                }
                Shutdown();
                return;
            }
        }
    }

    public static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
