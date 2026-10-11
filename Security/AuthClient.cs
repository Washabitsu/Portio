using Portio.Interfaces;
using Portio.Models;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace Portio.Security
{
    /// <summary>
    /// Talks to Projectio server to server. The browser never sees these calls
    /// </summary>
    public class AuthClient : IAuthClient
    {
        private readonly HttpClient _http;
        private readonly AuthSettings _settings;

        public AuthClient(HttpClient http, AuthSettings settings)
        {
            _http = http;
            _settings = settings;
        }


        public async Task<TokenResponse?> ExchangeCodeAsync(string code, string codeVerifier)
        {
            var response = await _http.PostAsJsonAsync("api/Auth/exchange", new
            {
                ExchangeCode = code,
                CodeVerifier = codeVerifier,
                RedirectUri = _settings.RedirectUri,
                ClientId = _settings.ClientId,
                ClientSecret = _settings.ClientSecret
            });

            if (!response.IsSuccessStatusCode)
                return null;

            return await response.Content.ReadFromJsonAsync<TokenResponse>();
        }

        public async Task<TokenResponse?> RefreshAsync(string refreshToken)
        {
            var response = await _http.PostAsJsonAsync("api/Auth/refresh", new
            {
                RefreshToken = refreshToken,
                ClientId = _settings.ClientId,
                ClientSecret = _settings.ClientSecret
            });

            // 400/401 is Projectio's answer "this refresh token is not valid (anymore)": null.
            // Anything else (Projectio is down or has an error) is not an answer about the token: exception
            if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized)
                return null;
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadFromJsonAsync<TokenResponse>();
        }

        public async Task RevokeAsync(string refreshToken)
        {
            await _http.PostAsJsonAsync("api/Auth/revoke", new
            {
                RefreshToken = refreshToken,
                ClientId = _settings.ClientId,
                ClientSecret = _settings.ClientSecret
            });
        }

        public async Task<string?> GetUserAsync(string accessToken)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "api/Account");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _http.SendAsync(request);
            if (!response.IsSuccessStatusCode)
                return null;

            return await response.Content.ReadAsStringAsync();
        }
    }
}
