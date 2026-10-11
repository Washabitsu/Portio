namespace Portio.Models
{
    /// <summary>
    /// Kept in an encrypted cookie between /bff/login and /bff/callback
    /// </summary>
    public class LoginState
    {
        public string State { get; set; } = string.Empty;
        public string CodeVerifier { get; set; } = string.Empty;
        public string ReturnUrl { get; set; } = "/";
    }
}
