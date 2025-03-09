using System.Collections.Generic;
using System.IO;
using System.Text.Json;

public static class PasswordHasher
{
    public static string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, workFactor: 11);
    }

    public static bool VerifyPassword(string password, string hashedPassword)
    {
        return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
    }

    public static void UpdateUserPassword(string username, string newPassword, List<UserData> users, string usersFilePath)
    {
        var user = users.FirstOrDefault(u => u.Username == username);
        
        if (user != null)
        {
            user.HashedPassword = HashPassword(newPassword);
            user.PasswordLastChanged = DateTime.Now;
            user.PasswordExpired = false;
            
            File.WriteAllText(usersFilePath, 
                JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true }));
        }
    }
} 