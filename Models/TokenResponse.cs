namespace Portio.Models
{
    /// <summary>
    /// What Projectio returns from /api/auth/exchange and /api/auth/refresh
    /// </summary>
    public class TokenResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public int ExpiresIn { get; set; }
        public string TokenType { get; set; } = string.Empty;
    }
}
