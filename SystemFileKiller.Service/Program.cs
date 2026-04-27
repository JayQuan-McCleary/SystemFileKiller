using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SystemFileKiller.Core;
using SystemFileKiller.Service;

PrivilegeManager.TryEnableDebugPrivilege();

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddHostedService<Worker>();
builder.Services.AddWindowsService(o => o.ServiceName = "SystemFileKiller");

await builder.Build().RunAsync();
