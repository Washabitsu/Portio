using Portio.Models;

namespace Portio.Interfaces
{
    public interface IAuthClient
    {
        public Task<TokenResponse?> ExchangeCodeAsync(string code, string codeVerifier);
        public Task<TokenResponse?> RefreshAsync(string refreshToken);
        public Task RevokeAsync(string refreshToken);
        public Task<string?> GetUserAsync(string accessToken);
    }
}
