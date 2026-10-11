using Portio.Interfaces;
using Portio.Models;
using Portio.Security;

namespace Portio.MiddleWare
{
    /// <summary>
    /// Runs on every request: session cookie -> session -> HttpContext.Items["session"].
    /// Refreshes the access token when it is about to expire.
    /// It doesn't block anything - endpoints decide if they need a session
    /// </summary>
    public class SessionMiddleware
    {
        private readonly RequestDelegate _next;

        public SessionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        // Scoped services are injected here, not in the constructor (middleware is created once)
        public async Task InvokeAsync(HttpContext context, ISessionHandler sessionHandler, IAuthClient authClient)
        {
            var sessionId = context.Request.Cookies[CookieSettings.SessionCookie];
            if (sessionId != null)
            {
                var session = await sessionHandler.GetSessionAsync(sessionId);

                if (session != null && session.ExpiresAt <= DateTimeOffset.UtcNow.AddSeconds(30))
                    session = await RefreshSession(sessionId, sessionHandler, authClient);

                if (session != null)
                {
                    context.Items["session_id"] = sessionId;
                    context.Items["session"] = session;
                }
                else
                {
                    // Session is gone (expired, server restarted or refresh failed)
                    context.Response.Cookies.Delete(CookieSettings.SessionCookie, CookieSettings.Session());
                }
            }

            await _next(context);
        }

        /// <summary>
        /// A refresh token works only once, so two requests of the same session must never refresh at the same time
        /// (the dashboard sends several requests at once). 64 locks are shared by all sessions:
        /// a session always gets the same one, and sessions that share a lock just wait for each other for a moment
        /// </summary>
        private static readonly SemaphoreSlim[] RefreshLocks = Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1)).ToArray();

        private static async Task<UserSession?> RefreshSession(string sessionId, ISessionHandler sessionHandler, IAuthClient authClient)
        {
            var refreshLock = RefreshLocks[(uint)sessionId.GetHashCode() % RefreshLocks.Length];
            await refreshLock.WaitAsync();
            try
            {
                // While we waited for the lock, another request may have refreshed already - then use what it saved
                var current = await sessionHandler.GetSessionAsync(sessionId);
                if (current == null)
                    return null;
                if (current.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
                    return current;

                TokenResponse? tokens;
                try
                {
                    tokens = await authClient.RefreshAsync(current.RefreshToken);
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
                {
                    // Projectio can't be reached right now. That says nothing about the session, so keep it
                    // and try again with the next request. Until then the services may refuse the old token
                    return current;
                }

                if (tokens == null)
                {
                    // The lock only covers this process. With several Portio instances another one can refresh
                    // at the same time: our refresh token is rotated away then. Give it a moment to save and use its result
                    await Task.Delay(500);
                    var latest = await sessionHandler.GetSessionAsync(sessionId);
                    if (latest != null && latest.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
                        return latest;

                    await sessionHandler.Logout(sessionId);
                    return null;
                }

                var refreshed = UserSession.FromTokens(tokens);
                refreshed.StartedAt = current.StartedAt;
                await sessionHandler.UpdateSessionAsync(sessionId, refreshed);
                return refreshed;
            }
            finally
            {
                refreshLock.Release();
            }
        }
    }
}
