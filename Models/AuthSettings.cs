namespace Portio.Models
{
    /// <summary>
    /// The "Auth" section of the configuration. ClientSecret comes from the .env file
    /// </summary>
    public class AuthSettings
    {
        public string Authority { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
        public string FrontendUrl { get; set; } = string.Empty;

        /// <summary>
        /// The only /api paths that are passed on without a session:
        /// - Projectio's login endpoints, the pages the browser visits while it logs in (there is no session yet).
        ///   Portio passes them through, so the browser never talks to Projectio directly
        /// - OrchestrML's prediction endpoint for machine clients, which sign in with an API key instead
        /// </summary>
        public string[] PublicPaths { get; set; } = [];

        public bool IsPublicPath(PathString path)
        {
            return PublicPaths.Any(publicPath => path.StartsWithSegments(publicPath));
        }
    }
}
