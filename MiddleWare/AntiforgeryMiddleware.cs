using Microsoft.AspNetCore.Antiforgery;
using Portio.Models;

namespace Portio.MiddleWare
{
    /// <summary>
    /// CSRF check for every request that changes something (POST, PUT, PATCH, DELETE),
    /// both our own controllers and the proxied /api routes.
    /// The SPA gets the token from /bff/csrf-token and sends it in the X-XSRF-TOKEN header.
    /// The public paths are skipped. Nothing there is done with our session cookie, so there is nothing to forge:
    /// Google posts the login result back from its own site (protected by the login handler's state check),
    /// and machine clients send an API key, not a cookie
    /// </summary>
    public class AntiforgeryMiddleware
    {
        private readonly RequestDelegate _next;

        public AntiforgeryMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IAntiforgery antiforgery, AuthSettings settings)
        {
            var method = context.Request.Method;
            var isSafe = HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method);

            if (!isSafe && !settings.IsPublicPath(context.Request.Path) && !await antiforgery.IsRequestValidAsync(context))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Missing or invalid CSRF token");
                return;
            }

            await _next(context);
        }
    }
}
