
using Microsoft.AspNetCore.DataProtection;
using Portio.Interfaces;
using Portio.MiddleWare;
using Portio.Models;
using Portio.Security;
using System.Net.Http.Headers;
using Yarp.ReverseProxy.Transforms;

DotNetEnv.Env.NoClobber().Load(".env");

var builder = WebApplication.CreateBuilder(args);

// The largest request Portio accepts. Dataset uploads for OrchestrML pass through here,
// and the web server's own default (about 28 MB) is too small for them
var maxUploadMegabytes = builder.Configuration.GetValue("Uploads:MaxMegabytes", 200);
builder.WebHost.ConfigureKestrel(kestrel => kestrel.Limits.MaxRequestBodySize = maxUploadMegabytes * 1024L * 1024L);


var authSettings = builder.Configuration.GetSection("Auth").Get<AuthSettings>()
    ?? throw new InvalidOperationException("Auth settings are not configured properly. Check appsettings.json.");
if (string.IsNullOrEmpty(authSettings.ClientSecret))
    throw new InvalidOperationException("Auth:ClientSecret is missing. Add Auth__ClientSecret to the .env file.");

// Addresses are joined with paths later, so make the slashes predictable
authSettings.Authority = authSettings.Authority.TrimEnd('/') + "/";
authSettings.FrontendUrl = authSettings.FrontendUrl.TrimEnd('/');

builder.Services.AddSingleton(authSettings);

// Sessions are kept in Redis when Redis__Configuration is set: they survive a restart and can be shared
// between several Portio instances. Without it they stay in this process (enough for local development)
var redis = builder.Configuration["Redis:Configuration"];
if (string.IsNullOrEmpty(redis))
{
    builder.Services.AddDistributedMemoryCache();
}
else
{
    builder.Services.AddStackExchangeRedisCache(options =>
    {
        options.Configuration = redis;
        options.InstanceName = "portio:";
    });
}

// The keys that encrypt the sessions and the login cookie. In a container they must be stored
// outside of it (DataProtection__KeysPath = a mounted folder), otherwise every restart logs everyone out
var dataProtection = builder.Services.AddDataProtection();
var keysPath = builder.Configuration["DataProtection:KeysPath"];
if (!string.IsNullOrEmpty(keysPath))
    dataProtection.PersistKeysToFileSystem(new DirectoryInfo(keysPath));

builder.Services.AddScoped<ITokenVault, TokenVault>();
builder.Services.AddScoped<ISessionHandler, SessionHandler>();
builder.Services.AddHttpClient<IAuthClient, AuthClient>(client =>
    client.BaseAddress = new Uri(authSettings.Authority));

builder.Services.AddAntiforgery(o =>
{
    o.HeaderName = "X-XSRF-TOKEN";
    o.Cookie.Name = "__Host-Portio.AF";
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.SameSite = SameSiteMode.Strict;
});

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Everything under /api is forwarded to the services, the rest to the SPA (routes are in appsettings.json)
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(transforms =>
    {
        // The SPA route only serves public files, it never gets a token
        if (transforms.Route.ClusterId == "spa")
            return;

        transforms.AddRequestTransform(context =>
        {
            if (authSettings.IsPublicPath(context.HttpContext.Request.Path))
            {
                // Public paths: Projectio needs its own login cookies, but Portio's cookies (the session) stay here
                var cookies = string.Join("; ", context.HttpContext.Request.Headers.Cookie.ToArray())
                    .Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                    .Where(cookie => !cookie.StartsWith("__Host-Portio."));

                context.ProxyRequest.Headers.Remove("Cookie");
                if (cookies.Any())
                    context.ProxyRequest.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", cookies));

                // These endpoints are public, a token has no business there
                context.ProxyRequest.Headers.Authorization = null;
            }
            else if (context.HttpContext.Items["session"] is UserSession session)
            {
                // Services: swap the session for the user's access token
                context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.AccessToken);
            }
            return ValueTask.CompletedTask;
        });
    });


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// For every response: no guessing of content types, no display inside another site's frame (clickjacking),
// and no address of ours in the Referer header of links that lead away
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});

app.UseMiddleware<SessionMiddleware>();
app.UseMiddleware<AntiforgeryMiddleware>();

app.MapControllers();

// An /api path that no service route matches is an error, it must not fall through to the SPA
app.Map("/api/{**rest}", () => Results.NotFound());

app.MapReverseProxy(proxy =>
{
    proxy.Use(async (context, next) =>
    {
        // The services need a logged in user. The SPA files and the public paths don't
        var needsSession = context.Request.Path.StartsWithSegments("/api") && !authSettings.IsPublicPath(context.Request.Path);
        if (needsSession && context.Items["session"] is not UserSession)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        await next();
    });
    proxy.UseSessionAffinity();
    proxy.UseLoadBalancing();
    proxy.UsePassiveHealthChecks();
});

app.Run();
