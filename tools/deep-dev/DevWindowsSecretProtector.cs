using Deep.Client.Shared.Persistence;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;
using System.Runtime.Versioning;

// Local operator probe storage, not an alternate account/authority path.
[SupportedOSPlatform("windows")]
internal sealed class DevWindowsSecretProtector : IDeepSecretProtector
{
    private readonly IDataProtector protector;
    internal DevWindowsSecretProtector(string directory)
    {
        DevOfflineAuthorityRenewal.RequireNoLinks(directory);
        Directory.CreateDirectory(directory);
        var provider=DataProtectionProvider.Create(new DirectoryInfo(directory),builder=>
            builder.SetApplicationName("Deep.Dev.OwnedClient").ProtectKeysWithDpapi());
        protector=provider.CreateProtector("Deep.Dev.Windows.Client.SecureStorage");
    }
    public byte[] Protect(ReadOnlySpan<byte> plaintext)
    {var owned=plaintext.ToArray();try{return protector.Protect(owned);}finally{CryptographicOperations.ZeroMemory(owned);}}
    public byte[] Unprotect(ReadOnlySpan<byte> protectedBytes)
    {var owned=protectedBytes.ToArray();try{return protector.Unprotect(owned);}finally{CryptographicOperations.ZeroMemory(owned);}}
}
