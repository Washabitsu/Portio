using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Portio.Interfaces;
using Portio.Models;
using Portio.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Portio.Controllers
{
    /// <summary>
    /// The BFF's own endpoints. Everything under /api is proxied to the services instead
    /// </summary>
    [Route("bff")]
    [ApiController]
    public class BffController : ControllerBase
    {
        private readonly ISessionHandler _sessionHandler;
        private readonly IAntiforgery _antiforgery;
        private readonly IAuthClient _authClient;
        private readonly ITokenVault _tvault;
        private readonly AuthSettings _settings;

        public BffController(ISessionHandler sessionHandler, IAntiforgery antiforgery, IAuthClient authClient, ITokenVault tvault, AuthSettings settings)
        {
            _sessionHandler = sessionHandler;
            _antiforgery = antiforgery;
            _authClient = authClient;
            _tvault = tvault;
            _settings = settings;
        }


        /// <summary>
        /// Step 1 - The SPA navigates here. We create state + PKCE and send the browser to Projectio's
        /// authorize endpoint. The address is our own: Portio passes /api/OIDC through to Projectio
        /// </summary>
        [HttpGet("login")]
        public IActionResult Login([FromQuery] string? returnUrl)
        {
            var login = new LoginState
            {
                State = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
                CodeVerifier = PkceToolset.CreateCodeVerifier(),
                // Only paths on our own site, otherwise /bff/login?returnUrl=https://evil.com works
                // ("~/..." also counts as local for IsLocalUrl, but it would be glued to our address without a slash)
                ReturnUrl = Url.IsLocalUrl(returnUrl) && returnUrl!.StartsWith('/') ? returnUrl : "/"
            };

            // Remember state + verifier in an encrypted cookie until the callback
            Response.Cookies.Append(CookieSettings.LoginCookie, _tvault.Seal(JsonSerializer.Serialize(login)), CookieSettings.Login());

            var url = "/api/OIDC/authorize" +
                $"?client_id={Uri.EscapeDataString(_settings.ClientId)}" +
                $"&redirect_uri={Uri.EscapeDataString(_settings.RedirectUri)}" +
                "&response_type=code" +
                $"&state={login.State}" +
                $"&code_challenge={PkceToolset.CreateCodeChallenge(login.CodeVerifier)}" +
                "&code_challenge_method=S256";

            return Redirect(url);
        }

        /// <summary>
        /// Step 2 - Projectio sends the browser back with a one-time code.
        /// We check state, swap the code for tokens and create the session
        /// </summary>
        [HttpGet("callback")]
        public async Task<IActionResult> Callback([FromQuery] string? code, [FromQuery] string? state)
        {
            var login = ReadLoginCookie();
            Response.Cookies.Delete(CookieSettings.LoginCookie, CookieSettings.Login());

            // state must match the one this browser started with (login CSRF protection)
            if (login == null || code == null || state == null || !SameValue(login.State, state))
                return BadRequest("Invalid login request. Please try again.");

            var tokens = await _authClient.ExchangeCodeAsync(code, login.CodeVerifier);
            if (tokens == null)
                return BadRequest("Login failed. Please try again.");

            // Always a new session id after login, never reuse an old one
            var oldSessionId = Request.Cookies[CookieSettings.SessionCookie];
            if (oldSessionId != null)
                await _sessionHandler.Logout(oldSessionId);

            var sessionId = await _sessionHandler.CreateSessionAsync(UserSession.FromTokens(tokens));
            Response.Cookies.Append(CookieSettings.SessionCookie, sessionId, CookieSettings.Session());

            return Redirect(_settings.FrontendUrl + login.ReturnUrl);
        }

        /// <summary>
        /// "Who am I?" - the SPA calls this on every page load. 401 means not logged in
        /// </summary>
        [HttpGet("user")]
        public async Task<IActionResult> GetUser()
        {
            if (HttpContext.Items["session"] is not UserSession session)
                return Unauthorized();

            var user = await _authClient.GetUserAsync(session.AccessToken);
            if (user == null)
                return Unauthorized();

            return Content(user, "application/json");
        }

        [HttpGet("csrf-token")]
        public IActionResult GetCsrfToken()
        {
            var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
            return Ok(new { token = tokens.RequestToken });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            if (HttpContext.Items["session"] is UserSession session && HttpContext.Items["session_id"] is string sessionId)
            {
                try
                {
                    await _authClient.RevokeAsync(session.RefreshToken);
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
                {
                    // Projectio can't be reached: the logout here must still happen
                }

                await _sessionHandler.Logout(sessionId);
            }

            Response.Cookies.Delete(CookieSettings.SessionCookie, CookieSettings.Session());
            return NoContent();
        }


        private LoginState? ReadLoginCookie()
        {
            var cookie = Request.Cookies[CookieSettings.LoginCookie];
            if (cookie == null)
                return null;

            try
            {
                return JsonSerializer.Deserialize<LoginState>(_tvault.Open(cookie));
            }
            catch (Exception)
            {
                // Tampered with or encrypted with old keys
                return null;
            }
        }

        private static bool SameValue(string a, string b)
        {
            return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
        }
    }
}
