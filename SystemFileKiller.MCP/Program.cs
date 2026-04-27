using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using SystemFileKiller.Core;

// Handle UAC self-elevate args before spinning up the MCP host. When this exe is re-launched
// under "runas" by ElevationHelper.ElevateAndKill / ElevateAndStopService, perform the op,
// write its result to the temp file, and exit — do NOT start the MCP server.
var elevatedExitCode = ElevationHelper.TryHandleElevatedArgs(args);
if (elevatedExitCode.HasValue)
    return elevatedExitCode.Value;

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.ClearProviders();

builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithToolsFromAssembly();

await builder.Build().RunAsync();
return 0;
