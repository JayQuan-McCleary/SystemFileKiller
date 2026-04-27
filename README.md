# System File Killer (SFK)

Anti-malware defense toolkit for Windows. Force-kills protected processes, deletes locked files, scans the registry for persistence entries, and analyzes binaries for malware indicators.

Surfaces:

- **CLI** (`sfk.exe`) — scriptable terminal interface
- **GUI** (`SystemFileKiller.GUI.exe`) — WPF app
- **MCP server** — exposes every operation as tools for Claude Code, Claude Agent SDK, and other AI agents
- **Helper service** (`SystemFileKiller.Service.exe`) — optional LocalSystem service used as a privilege-escalation back-end for `sfk_process_kill`

---

## Architecture

```
SystemFileKiller.Core      Library: ProcessKiller, FileDestroyer, RegistryCleaner,
                           ServiceManager, ElevationHelper, PipeClient, PrivilegeManager
SystemFileKiller.CLI       Console exe (sfk.exe). Wraps Core for terminal use
SystemFileKiller.GUI       WPF app. Wraps Core with a clickable surface
SystemFileKiller.MCP       MCP server exe. Exposes Core via stdio MCP tools
SystemFileKiller.Service   Worker SDK exe. Listens on \\.\pipe\sfk as LocalSystem
```

The MCP server is registered in [.mcp.json](.mcp.json) at repo root, so AI agents that load this repo see all `sfk_*` tools automatically.

---

## MCP Tools

These tools are auto-discovered by Claude Code (and any MCP-compatible client) when the repo is opened. AI agents can call any of them directly. All return JSON; success / failure is on the response.

### Process tools

#### `sfk_process_list`

List every running process.

```jsonc
// returns: array of { Pid, Name, FilePath, MemoryMB, Description }
```

#### `sfk_process_search`

Substring search across name and path (case-insensitive).

| Param | Type | Description |
|---|---|---|
| `filter` | string | Substring matched against process name or file path |

#### `sfk_process_kill`

**The headline tool.** Walks a 5-stage escalation ladder and returns on first success. Each stage emits a breadcrumb in the response `trace` array — read it to see which tier did the work.

| Param | Type | Default | Description |
|---|---|---|---|
| `target` | string | — | PID (number-as-string) or process name |
| `killTree` | bool | `false` | Also kill all child processes |
| `useElevation` | bool | `false` | Allow Stage 5 (UAC self-elevate via `runas`) as a final fallback. Off by default — UAC mid-call is jarring; opt-in per call |

Response shape:

```jsonc
{
  "pid": 1234,
  "result": "StoppedViaPipeService",
  "success": true,
  "trace": [
    "Stage1:Process.Kill:Exception:Win32Exception",
    "Stage2:NtTerminate:AccessDenied",
    "Stage3:StopService:CloudflareWARP:AccessDenied",
    "Stage4:PipeService:ok"
  ],
  "lastError": null
}
```

`result` values: `Success`, `StoppedViaService`, `StoppedViaPipeService`, `StoppedViaUac`, `NotFound`, `AccessDenied`, `Failed`. The four "stopped" variants all imply success; `success: true` covers them all.

**The escalation ladder:**

| Stage | Tier | What it does | Catches |
|---|---|---|---|
| 1 | — | `Process.Kill()` | Normal user-mode processes |
| 2 | — | Suspend all threads + `NtTerminateProcess` | Watchdog/respawn loops |
| 3 | Tier 2 | Look up service hosting the PID via WMI; stop via SCM | Service-managed processes (Dell stack, Razer suite, SupportAssist, Cloudflare WARP) — SCM checks the *service* DACL not the *process* DACL, so admins succeed where `OpenProcess` returned AccessDenied |
| 4 | Tier 4 | Forward to LocalSystem helper service via named pipe `\\.\pipe\sfk` | Anything an admin can do, without needing a UAC prompt — but only if the helper service is installed |
| 5 | Tier 3 | Re-launch this exe with `runas` (UAC), retry the kill, write result to a temp file | Catch-all when the helper service isn't installed and we're un-elevated |

Tier 1 (`SeDebugPrivilege`) is enabled at process startup via `PrivilegeManager.TryEnableDebugPrivilege()` — affects every stage's effective permissions, not a stage of its own.

PPL-protected processes (Defender, anything signed as a protected process) are intentionally **not** handled. `MsMpEng.exe` will return `AccessDenied` even with all five stages — that's Tier 5 (PPL bypass) and out of scope.

### Service tools

These are useful as targeted alternatives to `sfk_process_kill` when you already know a process is service-hosted, or when you want to inventory what's hosted by a stuck PID.

#### `sfk_service_list`

| Param | Type | Default | Description |
|---|---|---|---|
| `runningOnly` | bool | `false` | Filter to services in `Running` state |

Returns `{ count, services: [{ Name, DisplayName, Status, ProcessId }] }`. **Use the `Name` (short name) field for `sfk_service_stop`, not the display name** — `CloudflareWARP`, not `Cloudflare WARP`.

#### `sfk_service_stop`

| Param | Type | Default | Description |
|---|---|---|---|
| `name` | string | — | Service short name (Win32_Service.Name) |
| `timeoutSec` | int | `15` | Wait timeout for service to reach Stopped |

Returns `{ name, result, success }`. `result`: `Success`, `AlreadyInTargetState`, `NotFound`, `AccessDenied`, `Timeout`, `Failed`.

#### `sfk_service_for_pid`

| Param | Type | Description |
|---|---|---|
| `pid` | int | Process ID to look up |

Returns `{ pid, serviceCount, services: [...] }`. Empty services array means the PID is not service-hosted.

### File tools

| Tool | Purpose |
|---|---|
| `sfk_file_delete` | Force-delete a file. Tries direct delete → handle-unlock → rename trick → reboot-delete |
| `sfk_file_delete_dir` | Recursive force-delete of a directory tree |
| `sfk_file_unlock` | Find & close all open handles to a file. Reports holding processes. Does NOT delete |
| `sfk_file_reboot_delete` | Schedule deletion via `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`. Last resort |

### Registry tools

| Tool | Purpose |
|---|---|
| `sfk_registry_scan` | Scan all known persistence locations (Run, RunOnce, Services, Winlogon, Shell Folders, etc) and flag suspicious entries |
| `sfk_registry_scan_suspicious` | Same as above but returns ONLY flagged entries |
| `sfk_registry_remove` | Remove a specific entry by hive path + value name |

### Analysis tools

| Tool | Purpose |
|---|---|
| `sfk_analyze_file` | SHA256, size, timestamps, digital signature status, signer info, version info |
| `sfk_malwarebytes_detections` | Parse `C:\ProgramData\Malwarebytes\MBAMService\MwacDetections\*.json` and return a structured summary of every blocked threat |

---

## Recipes for AI agents

**"Kill this stubborn process":** Just call `sfk_process_kill <pid>`. The ladder handles escalation. Read the `trace` to see what worked. If it returns `AccessDenied` and `useElevation` was false, retry with `useElevation: true` to UAC-prompt the user.

**"What service is this PID running?":** `sfk_service_for_pid <pid>`. Empty list → not service-hosted. Non-empty → consider `sfk_service_stop` instead of `sfk_process_kill` if the user is admin.

**"Stop the Cloudflare WARP daemon":** `sfk_service_stop CloudflareWARP` — clean. Don't `sfk_process_kill warp-svc` first; it'll fall through Stages 1-3 anyway.

**"Find all Dell agents":** `sfk_service_list runningOnly:true`, then filter the response client-side for `Dell` in `Name` or `DisplayName`.

**"Is this file legit?":** `sfk_analyze_file <path>` — gives signer + SHA256. Cross-reference signer against the publisher you'd expect.

---

## Helper service (Tier 4)

The helper service runs as `LocalSystem` and listens on `\\.\pipe\sfk`. The pipe ACL grants:

- `LocalSystem` — FullControl
- `BuiltinAdministrators` — FullControl
- `Interactive` (logged-in user) — Read/Write/Synchronize

This means an **un-elevated** AI agent can call `sfk_process_kill <pid>` and the kill is performed as SYSTEM via the pipe — **no UAC prompt fires**. That's the whole point of the rewrite.

The service refuses to kill the critical-process blocklist (`csrss`, `wininit`, `services`, `lsass`, `smss`, `winlogon`, `system`, `registry`) regardless of caller — those bluescreen the box.

### Install

```powershell
# Elevated PowerShell:
.\install-service.ps1                  # Manual start (default)
.\install-service.ps1 -StartType Automatic   # Boot start

sc.exe start SystemFileKiller          # Bring it up the first time
```

### Verify

```powershell
Get-Service SystemFileKiller            # Should be Running
```

Then from any context (elevated or not):

```jsonc
// MCP call
sfk_process_kill 1234
// trace will end in "Stage4:PipeService:ok" when Stages 1-3 all return AccessDenied
```

### Uninstall

```powershell
.\uninstall-service.ps1
.\uninstall-service.ps1 -KeepFiles    # Service removed, files left
```

---

## Build

```powershell
dotnet build SystemFileKiller.slnx -c Release

# Republish MCP after Core changes:
dotnet publish SystemFileKiller.MCP/SystemFileKiller.MCP.csproj -c Release `
  -o SystemFileKiller.MCP/publish

# Then restart Claude Code (the MCP exe is loaded in-process and doesn't pick up disk changes mid-session)
```

---

## CLI reference

```
sfk process list                        List all running processes
sfk process kill <pid|name>             Force-kill a process (5-stage ladder)
sfk process kill-tree <pid|name>        Kill process and all children

sfk file delete <path>                  Force-delete a file
sfk file delete-dir <path>              Force-delete a directory tree
sfk file unlock <path>                  Unlock file handles (no delete)
sfk file reboot-delete <path>           Schedule deletion on reboot

sfk registry scan                       Scan all persistence locations
sfk registry scan-suspicious            Scan for suspicious entries only
sfk registry clean <index>              Remove entry by scan index (interactive confirm)
sfk registry clean-all                  Remove all suspicious entries (interactive confirm)
```

Run elevated for full functionality.
