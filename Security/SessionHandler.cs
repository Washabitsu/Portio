using Microsoft.Extensions.Caching.Distributed;
using Portio.Interfaces;
using Portio.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Portio.Security
{
    public class SessionHandler : ISessionHandler
    {
        private readonly ITokenVault _tvault;
        private readonly IDistributedCache _cache;

        public SessionHandler(ITokenVault vault, IDistributedCache cache)
        {
            _tvault = vault;
            _cache = cache;
        }


        public async Task<string> CreateSessionAsync(UserSession session)
        {
            var sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            await Save(sessionId, session);
            return sessionId;
        }

        public async Task<UserSession?> GetSessionAsync(string sessionId)
        {
            var sealedSession = await _cache.GetStringAsync(Key(sessionId));
            if (sealedSession == null)
                return null;

            try
            {
                var json = _tvault.Open(sealedSession);
                return JsonSerializer.Deserialize<UserSession>(json);
            }
            catch (CryptographicException)
            {
                // Can't be decrypted (e.g. keys changed) - treat as logged out
                await _cache.RemoveAsync(Key(sessionId));
                return null;
            }
        }

        public Task UpdateSessionAsync(string sessionId, UserSession session)
        {
            return Save(sessionId, session);
        }

        public Task Logout(string sessionId)
        {
            return _cache.RemoveAsync(Key(sessionId));
        }


        private Task Save(string sessionId, UserSession session)
        {
            var sealedSession = _tvault.Seal(JsonSerializer.Serialize(session));

            // A session ends after 1 hour without requests, or 8 hours after login at most
            return _cache.SetStringAsync(Key(sessionId), sealedSession, new DistributedCacheEntryOptions
            {
                SlidingExpiration = TimeSpan.FromHours(1),
                AbsoluteExpiration = session.StartedAt.AddHours(8)
            });
        }

        /// <summary>
        /// The session id is the secret in the browser's cookie, so the store only gets its hash:
        /// someone who can read the store can't copy a session id out of it
        /// </summary>
        private static string Key(string sessionId)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sessionId));
            return "session:" + Convert.ToHexString(hash);
        }
    }
}
