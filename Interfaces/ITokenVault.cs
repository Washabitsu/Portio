namespace Portio.Interfaces
{
    public interface ITokenVault
    {
        public string Seal(string token);
        public string Open(string sealedToken);
    }
}
