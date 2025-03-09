using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;
using System.Threading;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text.Json;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

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

// Certificate handling at startup
var certPath = builder.Configuration["Certificate:Path"]!;
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

// Load users from JSON
var users = new List<UserData>();
var usersFilePath = Path.Combine(Directory.GetCurrentDirectory(), "users.json");

void LoadUsers()
{
    if (File.Exists(usersFilePath))
    {
        users = JsonSerializer.Deserialize<List<UserData>>(File.ReadAllText(usersFilePath))!;
        Console.WriteLine("Users reloaded from file");
    }
}

// Set up file watcher for users.json
var watcher = new FileSystemWatcher(Path.GetDirectoryName(usersFilePath)!, Path.GetFileName(usersFilePath));
watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime;
watcher.Changed += (sender, e) => 
{
    // Small delay to ensure file is completely written
    Thread.Sleep(100);
    LoadUsers();
};
watcher.EnableRaisingEvents = true;

// Initial load of users
LoadUsers();

// Add JWT authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Get the actual host without protocol
        var host = builder.Configuration.GetValue<string>("ASPNETCORE_URLS", "localhost:5006")
            .Replace("http://", "")
            .Replace("*", "localhost");

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = $"http://{host}",
            ValidAudience = $"http://{host}",
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
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine("Token validated successfully");
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Authentication failed: {context.Exception.Message}");
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
