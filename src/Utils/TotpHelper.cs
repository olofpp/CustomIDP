using OtpNet;

public static class TotpHelper
{
    public static string GenerateKey()
    {
        var key = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(key);
    }

    public static string GenerateQrCodeUrl(string key, string username, string issuer)
    {
        var encodedIssuer = Uri.EscapeDataString(issuer);
        var encodedUsername = Uri.EscapeDataString(username);
        return $"otpauth://totp/{encodedIssuer}:{encodedUsername}?secret={key}&issuer={encodedIssuer}";
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