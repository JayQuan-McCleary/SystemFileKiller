namespace SystemFileKiller.Core;

/// <summary>
/// Per-call options + trace for the ProcessKiller escalation ladder.
/// Each stage appends a line to <see cref="Trace"/> describing what was tried and the outcome.
/// </summary>
public class KillEscalation
{
    /// <summary>Allow Stage 4: forward the kill to the LocalSystem helper service via named pipe.</summary>
    public bool AllowPipeService { get; init; } = true;

    /// <summary>Allow Stage 5: re-launch the host exe under UAC ("runas") and retry.</summary>
    public bool AllowUacElevation { get; init; } = false;

    /// <summary>Per-stage breadcrumbs: useful for surfacing in MCP responses when debugging stubborn kills.</summary>
    public List<string> Trace { get; } = new();

    internal void Note(string entry) => Trace.Add(entry);
}
