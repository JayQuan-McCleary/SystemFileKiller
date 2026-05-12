using System.Management;

namespace SystemFileKiller.Core;

public record WmiSubscription(
    string Namespace,
    string FilterName,
    string ConsumerName,
    string ConsumerType,
    string QueryLanguage,
    string Query,
    string CommandLineTemplate,
    string ExecutablePath);

/// <summary>
/// WMI event-subscription persistence. The <c>root\subscription</c> namespace holds
/// <c>__EventFilter</c> + <c>__EventConsumer</c> + <c>__FilterToConsumerBinding</c> triples;
/// the binding makes Windows execute the consumer's command whenever the filter's query fires.
/// A favorite of advanced persistence (PowerSploit, Cobalt Strike) because it survives reboot
/// without a Run-key or scheduled task and runs as SYSTEM.
/// </summary>
public static class WmiPersistenceUtil
{
    public static List<WmiSubscription> Scan()
    {
        var subs = new List<WmiSubscription>();
        var bindingScope = new ManagementScope(@"\\.\root\subscription");
        try { bindingScope.Connect(); }
        catch { return subs; }

        try
        {
            using var bindings = new ManagementObjectSearcher(bindingScope,
                new ObjectQuery("SELECT * FROM __FilterToConsumerBinding"));
            foreach (ManagementObject binding in bindings.Get())
            {
                try
                {
                    var filterPath = binding["Filter"]?.ToString() ?? "";
                    var consumerPath = binding["Consumer"]?.ToString() ?? "";

                    var (filterName, query, lang) = TryReadFilter(bindingScope, filterPath);
                    var (consumerName, consumerType, cmd, exe) = TryReadConsumer(bindingScope, consumerPath);

                    subs.Add(new WmiSubscription(
                        Namespace: "root\\subscription",
                        FilterName: filterName,
                        ConsumerName: consumerName,
                        ConsumerType: consumerType,
                        QueryLanguage: lang,
                        Query: query,
                        CommandLineTemplate: cmd,
                        ExecutablePath: exe));
                }
                catch { }
                binding.Dispose();
            }
        }
        catch { }
        return subs;
    }

    public static (bool Ok, string Message) RemoveByConsumerName(string consumerName)
    {
        if (string.IsNullOrWhiteSpace(consumerName)) return (false, "consumer name required");
        var scope = new ManagementScope(@"\\.\root\subscription");
        try { scope.Connect(); }
        catch (Exception ex) { return (false, $"connect failed: {ex.Message}"); }

        int removed = 0;
        try
        {
            // Find bindings referencing this consumer and remove them first
            using var bindings = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT * FROM __FilterToConsumerBinding"));
            foreach (ManagementObject b in bindings.Get())
            {
                if ((b["Consumer"]?.ToString() ?? "").Contains($"Name=\"{consumerName}\"", StringComparison.OrdinalIgnoreCase))
                {
                    try { b.Delete(); removed++; } catch { }
                }
                b.Dispose();
            }
            // Then the consumer itself
            foreach (var cls in new[] { "CommandLineEventConsumer", "ActiveScriptEventConsumer" })
            {
                using var consumers = new ManagementObjectSearcher(scope,
                    new ObjectQuery($"SELECT * FROM {cls} WHERE Name=\"{consumerName}\""));
                foreach (ManagementObject c in consumers.Get())
                {
                    try { c.Delete(); removed++; } catch { }
                    c.Dispose();
                }
            }
            return (removed > 0, removed > 0 ? $"removed {removed} object(s)" : "nothing matched");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static (string Name, string Query, string Lang) TryReadFilter(ManagementScope scope, string filterPath)
    {
        if (string.IsNullOrEmpty(filterPath)) return ("", "", "");
        try
        {
            var path = new ManagementPath(filterPath);
            using var obj = new ManagementObject(scope, path, null);
            obj.Get();
            return (
                obj["Name"]?.ToString() ?? "",
                obj["Query"]?.ToString() ?? "",
                obj["QueryLanguage"]?.ToString() ?? "");
        }
        catch { return ("", "", ""); }
    }

    private static (string Name, string Type, string Cmd, string Exe) TryReadConsumer(ManagementScope scope, string consumerPath)
    {
        if (string.IsNullOrEmpty(consumerPath)) return ("", "", "", "");
        try
        {
            var path = new ManagementPath(consumerPath);
            using var obj = new ManagementObject(scope, path, null);
            obj.Get();
            return (
                obj["Name"]?.ToString() ?? "",
                obj.ClassPath?.ClassName ?? "",
                obj["CommandLineTemplate"]?.ToString() ?? "",
                obj["ExecutablePath"]?.ToString() ?? "");
        }
        catch { return ("", "", "", ""); }
    }
}
