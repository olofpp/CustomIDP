using OtpNet;
using Microsoft.Extensions.Configuration;

public static class TotpHelper
{
    public static string GenerateKey()
    {
        var key = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(key);
    }

    public static string GenerateQrCodeUrl(string key, string username, IConfiguration configuration)
    {
        var issuerUrl = configuration["Jwt:Issuer"];
        var uri = new Uri(issuerUrl);
        var domain = uri.Host;  // This will extract just the domain name
        var encodedDomain = Uri.EscapeDataString(domain);
        var encodedUsername = Uri.EscapeDataString(username);
        return $"otpauth://totp/{encodedDomain}:{encodedUsername}?secret={key}&issuer={encodedDomain}";
    }

    public static bool ValidateCode(string key, string code)
    {
        try
        {
            var totp = new Totp(Base32Encoding.ToBytes(key));
            return totp.VerifyTotp(code, out _, new VerificationWindow(2, 2));
        }
        catch
        {
            return false;
        }
    }
} 