using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class SystemTools
{
    [McpServerTool(Name = "sfk_restore_point_create")]
    [Description("Create a System Restore checkpoint. Use BEFORE running a destructive batch — gives you a known-good system snapshot to roll back to via System Properties → System Protection → System Restore if cleanup catches something legitimate. Requires admin AND System Protection enabled on C:.")]
    public static string CreateRestorePoint(
        [Description("Free-text label for the checkpoint, shown in the System Restore UI")] string description = "SFK checkpoint")
    {
        var (r, msg) = RestorePointUtil.Create(description);
        return JsonSerializer.Serialize(new
        {
            description,
            result = r.ToString(),
            success = r == RestorePointResult.Success,
            message = msg
        });
    }
}
