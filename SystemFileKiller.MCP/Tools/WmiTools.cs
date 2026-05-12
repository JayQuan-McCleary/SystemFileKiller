using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class WmiTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    [McpServerTool(Name = "sfk_wmi_persistence_scan")]
    [Description("Scan the root\\subscription WMI namespace for event-subscription persistence (__EventFilter + __EventConsumer + __FilterToConsumerBinding triples). A favorite advanced-persistence mechanism — survives reboot without a Run key or scheduled task and runs as SYSTEM. Returns each binding with its trigger query and the consumer's command line / executable path.")]
    public static string ScanPersistence()
    {
        var subs = WmiPersistenceUtil.Scan();
        return JsonSerializer.Serialize(new
        {
            count = subs.Count,
            subscriptions = subs.Select(s => new
            {
                s.Namespace, s.FilterName, s.ConsumerName, s.ConsumerType,
                s.QueryLanguage, s.Query,
                s.CommandLineTemplate, s.ExecutablePath
            })
        }, Indented);
    }

    [McpServerTool(Name = "sfk_wmi_persistence_remove")]
    [Description("Remove a WMI subscription by consumer name. Deletes any __FilterToConsumerBinding referencing this consumer plus the consumer object itself. Requires admin.")]
    public static string RemovePersistence([Description("Consumer Name (from sfk_wmi_persistence_scan)")] string consumerName)
    {
        var (ok, msg) = WmiPersistenceUtil.RemoveByConsumerName(consumerName);
        return JsonSerializer.Serialize(new { consumerName, success = ok, message = msg });
    }
}
