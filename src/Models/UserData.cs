using System.Text.Json.Serialization;

public class UserData
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;
    
    [JsonPropertyName("firstName")]
    public string FirstName { get; set; } = string.Empty;
    
    [JsonPropertyName("lastName")]
    public string LastName { get; set; } = string.Empty;
    
    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;
    
    [JsonPropertyName("phone")]
    public string Phone { get; set; } = string.Empty;
    
    [JsonPropertyName("password")]
    public string HashedPassword { get; set; } = string.Empty;  // Will store BCrypt hash
    
    [JsonPropertyName("pin")]
    public string Pin { get; set; } = string.Empty;
    
    [JsonPropertyName("role")]
    public string Role { get; set; } = string.Empty;
    
    [JsonPropertyName("age")]
    public int Age { get; set; }
    
    [JsonPropertyName("appAccess")]
    public List<string> AppAccess { get; set; } = new();
    
    [JsonPropertyName("passwordLastChanged")]
    public DateTime PasswordLastChanged { get; set; } = DateTime.Now;
    
    [JsonPropertyName("passwordExpired")]
    public bool PasswordExpired { get; set; } = false;
    
    [JsonPropertyName("totpKey")]
    public string TotpKey { get; set; } = string.Empty;
    
    [JsonPropertyName("totpEnabled")]
    public bool TotpEnabled { get; set; } = false;
} 