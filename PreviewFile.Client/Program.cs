using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using PreviewFile.Service;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.Services.AddScoped<IPreviewFileService, PreviewFileService>();
builder.Services.AddScoped<IPdfService, PdfService>();

await builder.Build().RunAsync();
