using Portio.Models;

namespace Portio.Interfaces
{
    public interface ISessionHandler
    {
        public Task<string> CreateSessionAsync(UserSession session);
        public Task<UserSession?> GetSessionAsync(string sessionId);
        public Task UpdateSessionAsync(string sessionId, UserSession session);
        public Task Logout(string sessionId);
    }
}
