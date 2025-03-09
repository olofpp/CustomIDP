using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;
using System.Threading;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text.Json;
using Microsoft.Extensions.FileProviders;
using BCrypt.Net;

var builder = WebApplication.CreateBuilder(args);

// Configure to read from idp_conf folder
builder.Configuration.SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile(Path.Combine("idp_conf", "appsettings.json"), optional: false)
    .AddJsonFile(Path.Combine("idp_conf", $"appsettings.{builder.Environment.EnvironmentName}.json"), optional: true);

// Add CORS policy
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Update certificate path to use idp_conf folder
var certPath = Path.Combine("idp_conf", builder.Configuration["Certificate:Path"]!);
var certPassword = builder.Configuration["Certificate:Password"];

// Use X509Certificate2 with PFX file
X509Certificate2 cert;
try
{
    if (File.Exists(certPath))
    {
        cert = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.Exportable);
    }
    else
    {
        // Create and save new certificate if it doesn't exist
        cert = CreateAndSaveCertificate(certPath);
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Certificate error: {ex.Message}");
    // Create new certificate as fallback
    cert = CreateAndSaveCertificate(certPath);
}

var securityKey = new X509SecurityKey(cert);
var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256)
{
    CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
};

// Update users.json path to use idp_conf folder
var usersFilePath = Path.Combine(Directory.GetCurrentDirectory(), "idp_conf", "users.json");

var users = new List<UserData>();
var watcher = new FileSystemWatcher(Path.GetDirectoryName(usersFilePath)!, Path.GetFileName(usersFilePath));
watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime;
watcher.Changed += (sender, e) => 
{
    // Small delay to ensure file is completely written
    Thread.Sleep(100);
    LoadUsers();
};
watcher.EnableRaisingEvents = true;

void LoadUsers()
{
    if (File.Exists(usersFilePath))
    {
        users = JsonSerializer.Deserialize<List<UserData>>(File.ReadAllText(usersFilePath))!;
        
        // Check for and hash any plain text passwords
        bool needsUpdate = false;
        foreach (var user in users)
        {
            // If the password isn't a valid BCrypt hash, assume it's plain text
            if (!user.HashedPassword.StartsWith("$2"))
            {
                string plainTextPassword = user.HashedPassword;
                user.HashedPassword = BCrypt.Net.BCrypt.HashPassword(plainTextPassword);
                needsUpdate = true;
                Console.WriteLine($"Hashed password for user: {user.Username}");
            }
        }

        // Save updated hashes if any were changed
        if (needsUpdate)
        {
            string jsonContent = JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(usersFilePath, jsonContent);
            Console.WriteLine("Updated users.json with hashed passwords");
        }

        Console.WriteLine($"Loaded {users.Count} users from file");
    }
    else
    {
        Console.WriteLine($"Users file not found at: {usersFilePath}");
    }
}

// Initial load of users
LoadUsers();

// Add JWT authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new X509SecurityKey(cert),
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                context.Token = context.Request.Cookies["auth_token"];
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Use CORS before auth middleware
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

// Map all auth endpoints
app.MapAuthEndpoints(users, usersFilePath, signingCredentials, cert);

// Add after mapping auth endpoints
app.MapGet("/", () => Results.Redirect("/login"));

// Add before other middleware
var webRootPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");
if (!Directory.Exists(webRootPath))
{
    Directory.CreateDirectory(webRootPath);
}

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(webRootPath),
    RequestPath = ""
});

// Ensure idp_conf directory exists
var idpConfPath = Path.Combine(Directory.GetCurrentDirectory(), "idp_conf");
if (!Directory.Exists(idpConfPath))
{
    Directory.CreateDirectory(idpConfPath);
}

app.Run();

// Certificate helper functions
X509Certificate2 CreateAndSaveCertificate(string path)
{
    using var rsa = RSA.Create(2048);
    var req = new CertificateRequest(
        "CN=CustomIdp",
        rsa,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);

    var cert = req.CreateSelfSigned(
        DateTimeOffset.Now,
        DateTimeOffset.Now.AddYears(1));

    // Export to PFX with password
    var pfxBytes = cert.Export(X509ContentType.Pfx, "password");
    File.WriteAllBytes(path, pfxBytes);

    // Return a new certificate instance
    return new X509Certificate2(pfxBytes, "password", X509KeyStorageFlags.Exportable);
}
