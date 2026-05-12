namespace SystemFileKiller.Core;

/// <summary>
/// Wire format shared by <see cref="PipeClient"/> and the SystemFileKiller.Service pipe server.
/// Newline-delimited JSON, one request → one response per connection.
/// </summary>
public class PipeRequest
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Cmd { get; set; } = "";
    public int? Pid { get; set; }
    public string? Name { get; set; }
    public string? Path { get; set; }
    public string[]? Paths { get; set; }
    public bool KillTree { get; set; }
    /// <summary>Nested operations for <see cref="PipeProtocol.Commands.Batch"/>. Each entry is itself a PipeRequest dispatched in order.</summary>
    public PipeRequest[]? Ops { get; set; }
    /// <summary>Batch flag: if true, abort remaining ops on first failure. Default false — continue and report per-op outcomes.</summary>
    public bool StopOnError { get; set; }
    /// <summary>If true, ops report what they would do without performing destructive actions. Currently honored by batch.</summary>
    public bool DryRun { get; set; }
    /// <summary>Generic registry hive path, e.g. "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".</summary>
    public string? Hive { get; set; }
    /// <summary>Registry value name (used with hive). Empty string targets the default value.</summary>
    public string? ValueName { get; set; }
    /// <summary>Registry value data (for set_value).</summary>
    public string? ValueData { get; set; }
    /// <summary>Registry value kind: "String" (default), "ExpandString", "DWord", "QWord", "Binary", "MultiString".</summary>
    public string? ValueKind { get; set; }
    /// <summary>Quarantine bucket id (for restore).</summary>
    public string? QuarantineId { get; set; }
    /// <summary>Generic age-in-days bound for purge ops.</summary>
    public int? OlderThanDays { get; set; }
    /// <summary>Hostname regex for hosts_remove.</summary>
    public string? Pattern { get; set; }
    /// <summary>Free-text description for restore-point checkpoint and nuke playbook target.</summary>
    public string? Description { get; set; }
}

public class PipeResponse
{
    public string Id { get; set; } = "";
    public bool Ok { get; set; }
    public string? Result { get; set; }
    public string? Error { get; set; }
    /// <summary>Per-path outcomes for <c>delete_paths</c>.</summary>
    public List<PipePathResult>? Results { get; set; }
    /// <summary>Per-op outcomes for <c>batch</c> and <c>kill_process_by_name</c>. Each entry is the PipeResponse from the inner op's dispatch.</summary>
    public List<PipeResponse>? BatchResults { get; set; }
}

public class PipePathResult
{
    public string Path { get; set; } = "";
    public bool Ok { get; set; }
    public string? Result { get; set; }
    public string? Error { get; set; }
}

public static class PipeProtocol
{
    public const string PipeName = "sfk";

    public static class Commands
    {
        public const string Ping = "ping";

        // Processes
        public const string KillProcess = "kill_process";
        public const string KillProcessByName = "kill_process_by_name";

        // Services
        public const string StopService = "stop_service";
        public const string DisableService = "disable_service";
        public const string DeleteService = "delete_service";

        // Files
        public const string DeleteFile = "delete_file";
        public const string DeleteDir = "delete_dir";
        public const string DeletePaths = "delete_paths";

        // Scheduled tasks
        public const string TaskDisable = "task_disable";
        public const string TaskEnable = "task_enable";
        public const string TaskDelete = "task_delete";

        // Registry (generic)
        public const string RegistryRemoveKey = "registry_remove_key";
        public const string RegistryRemoveValue = "registry_remove_value";
        public const string RegistrySetValue = "registry_set_value";

        // Quarantine
        public const string QuarantineFile = "quarantine_file";
        public const string QuarantineRestore = "quarantine_restore";
        public const string QuarantinePurge = "quarantine_purge";

        // Hosts
        public const string HostsRemovePattern = "hosts_remove_pattern";

        // WMI persistence
        public const string WmiPersistenceRemove = "wmi_persistence_remove";

        // System
        public const string RestorePointCreate = "restore_point_create";

        // Multi-op
        public const string Batch = "batch";
    }
}
