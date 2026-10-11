using Microsoft.AspNetCore.DataProtection;
using Portio.Interfaces;

namespace Portio.Security
{
    public class TokenVault : ITokenVault
    {

        private readonly IDataProtector _protector;

        public TokenVault(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("Portio.Tokens.v1");
        }
        public string Seal(string token) => _protector.Protect(token);
        public string Open(string sealedToken) => _protector.Unprotect(sealedToken);
    }
}
