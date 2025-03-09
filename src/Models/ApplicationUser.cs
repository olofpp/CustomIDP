using Microsoft.AspNetCore.Identity;

public class ApplicationUser : IdentityUser
{
    public string TotpSecretKey { get; set; } = string.Empty;
    public string Pin { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public int Age { get; set; }
    public List<string> AppAccess { get; set; } = new();
} 