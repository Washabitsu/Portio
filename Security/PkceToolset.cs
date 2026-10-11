using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Portio.Security
{
    public static class PkceToolset
    {
        /// <summary>
        /// Random secret that stays in Portio. Only its hash (the challenge) is sent in the login URL
        /// </summary>
        public static string CreateCodeVerifier()
        {
            return Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        }

        public static string CreateCodeChallenge(string codeVerifier)
        {
            var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
            return Base64Url.EncodeToString(hash);
        }
    }
}
