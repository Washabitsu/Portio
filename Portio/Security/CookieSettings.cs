namespace Portio.Security
{
    /// <summary>
    /// Cookie names and options in one place, so creating and deleting always match
    /// </summary>
    public static class CookieSettings
    {
        public const string SessionCookie = "__Host-Portio.Session";
        public const string LoginCookie = "__Host-Portio.Login";

        public static CookieOptions Session()
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                IsEssential = true
            };
        }

        /// <summary>
        /// Lax, not Strict: the login comes back from another site (Google)
        /// and the browser would not send a Strict cookie with it
        /// </summary>
        public static CookieOptions Login()
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Path = "/",
                IsEssential = true,
                Expires = DateTimeOffset.UtcNow.AddMinutes(10)
            };
        }
    }
}
