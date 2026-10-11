namespace Portio.Models
{
    /// <summary>
    /// Everything we keep on the server for one logged in browser
    /// </summary>
    public class UserSession
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTimeOffset ExpiresAt { get; set; }
        public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;

        public static UserSession FromTokens(TokenResponse tokens)
        {
            return new UserSession
            {
                AccessToken = tokens.AccessToken,
                RefreshToken = tokens.RefreshToken,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(tokens.ExpiresIn)
            };
        }
    }
}
