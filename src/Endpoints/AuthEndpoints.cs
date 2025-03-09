using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using OtpNet;
using Microsoft.Extensions.FileProviders;
using Microsoft.AspNetCore.Http.HttpResults;
using BCrypt.Net;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app, List<UserData> users, string usersFilePath, SigningCredentials signingCredentials, X509Certificate2 cert)
    {
        // Well-known configuration endpoint
        app.MapGet("/.well-known/openid-configuration", () => new
        {
            issuer = app.Configuration["Jwt:Issuer"],
            jwks_uri = $"{app.Configuration["Jwt:Issuer"]}/.well-known/jwks",
            token_endpoint = $"{app.Configuration["Jwt:Issuer"]}/connect/token",
            response_types_supported = new[] { "token" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post" },
            grant_types_supported = new[] { "password" }
        });

        // JWKS endpoint
        app.MapGet("/.well-known/jwks", () =>
        {
            var rsaParams = cert.GetRSAPublicKey()!.ExportParameters(false);
            return new
            {
                keys = new[]
                {
                    new
                    {
                        kid = cert.Thumbprint,
                        kty = "RSA",
                        use = "sig",
                        alg = "RS256",
                        n = Base64UrlEncoder.Encode(rsaParams.Modulus!),
                        e = Base64UrlEncoder.Encode(rsaParams.Exponent!)
                    }
                }
            };
        });

        // Token endpoint
        app.MapPost("/connect/token", async (HttpContext context) =>
        {
            var form = await context.Request.ReadFormAsync();
            var username = form["username"].ToString();
            var password = form["password"].ToString();
            var totpCode = form["totp_code"].ToString();

            Console.WriteLine($"Login attempt for user: {username}");
            Console.WriteLine($"TOTP code provided: {!string.IsNullOrEmpty(totpCode)}");
            if (!string.IsNullOrEmpty(totpCode))
            {
                Console.WriteLine($"TOTP code length: {totpCode.Length}");
            }

            var user = users!.FirstOrDefault(u => u.Username == username);
            if (user == null || !PasswordHasher.VerifyPassword(password, user.HashedPassword))
            {
                Console.WriteLine("Authentication failed: Invalid username or password");
                return Results.Unauthorized();
            }

            Console.WriteLine($"User found, TOTP enabled: {user.TotpEnabled}");
            Console.WriteLine($"Password expired: {user.PasswordExpired}");
            Console.WriteLine($"TOTP key present: {!string.IsNullOrEmpty(user.TotpKey)}");

            // Check TOTP first if enabled
            if (user.TotpEnabled)
            {
                if (string.IsNullOrEmpty(totpCode))
                {
                    Console.WriteLine("TOTP required but not provided");
                    return Results.UnprocessableEntity(new { 
                        message = "TOTP code required",
                        requireTotp = true,
                        username = username,
                        requirePasswordChange = false  // Explicitly set to false
                    });
                }
                
                bool isValidTotp = TotpHelper.ValidateCode(user.TotpKey, totpCode);
                Console.WriteLine($"TOTP validation result: {isValidTotp}");
                
                if (!isValidTotp)
                {
                    Console.WriteLine("Invalid TOTP code provided");
                    return Results.UnprocessableEntity(new { 
                        message = "Invalid TOTP code",
                        requireTotp = true,
                        username = username,
                        requirePasswordChange = false  // Explicitly set to false
                    });
                }
                Console.WriteLine("TOTP validation successful");
            }

            // Only check password expiration after successful TOTP validation
            if (user.PasswordExpired)
            {
                Console.WriteLine("Password is expired");
                return Results.UnprocessableEntity(new { 
                    message = "Password expired", 
                    username = username,
                    requireTotp = false,  // Explicitly set to false
                    requirePasswordChange = true
                });
            }

            Console.WriteLine("Generating token...");
            // Generate token
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("age", user.Age.ToString()),
                new Claim("app_access", JsonSerializer.Serialize(user.AppAccess))
            };

            var token = new JwtSecurityToken(
                issuer: app.Configuration["Jwt:Issuer"],
                audience: app.Configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: signingCredentials);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            // Set the auth cookie
            context.Response.Cookies.Append("auth_token", tokenString, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTime.Now.AddHours(1)
            });

            Console.WriteLine("Login successful, token generated");
            return Results.Ok(new
            {
                access_token = tokenString,
                token_type = "Bearer",
                expires_in = 3600,
                domain = context.Request.Host.Host,
                issued_at = DateTime.UtcNow,
                expires_at = DateTime.UtcNow.AddHours(1)
            });
        });

        // Password update endpoint
        app.MapPost("/update-password", async (HttpContext context) =>
        {
            var form = await context.Request.ReadFormAsync();
            var username = form["username"].ToString();
            var currentPassword = form["current_password"].ToString();
            var newPassword = form["new_password"].ToString();

            var user = users!.FirstOrDefault(u => u.Username == username);
            
            if (user == null || !PasswordHasher.VerifyPassword(currentPassword, user.HashedPassword))
            {
                return Results.Unauthorized();
            }

            // Update the password
            user.HashedPassword = BCrypt.Net.BCrypt.HashPassword(newPassword);
            user.PasswordLastChanged = DateTime.UtcNow;
            user.PasswordExpired = false;

            // Save changes to file
            var jsonOptions = new JsonSerializerOptions 
            { 
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };

            await File.WriteAllTextAsync(usersFilePath, 
                JsonSerializer.Serialize(users, jsonOptions));

            // Generate new token and set cookie
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("age", user.Age.ToString()),
                new Claim("app_access", JsonSerializer.Serialize(user.AppAccess))
            };

            var token = new JwtSecurityToken(
                issuer: app.Configuration["Jwt:Issuer"],
                audience: app.Configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: signingCredentials);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            // Set the auth cookie
            context.Response.Cookies.Append("auth_token", tokenString, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTime.Now.AddHours(1)
            });

            return Results.Ok(new { 
                message = "Password updated successfully",
                redirectUrl = "/dashboard"
            });
        });

        // Admin endpoints
        app.MapPost("/admin/reset-password", async (HttpContext context) =>
        {
            var form = await context.Request.ReadFormAsync();
            var adminUsername = form["admin_username"].ToString();
            var adminPassword = form["admin_password"].ToString();
            var targetUsername = form["target_username"].ToString();
            var newPassword = form["new_password"].ToString();

            var admin = users!.FirstOrDefault(u => u.Username == adminUsername);
            if (admin == null || 
                !PasswordHasher.VerifyPassword(adminPassword, admin.HashedPassword) || 
                admin.Role != "Admin")
            {
                return Results.Unauthorized();
            }

            var targetUser = users!.FirstOrDefault(u => u.Username == targetUsername);
            if (targetUser == null)
            {
                return Results.NotFound(new { message = "User not found" });
            }

            PasswordHasher.UpdateUserPassword(targetUsername, newPassword, users, usersFilePath);
            return Results.Ok(new { message = $"Password updated for user {targetUsername}" });
        });

        app.MapPost("/admin/create-user", async (HttpContext context) =>
        {
            if (!context.User.IsInRole("Admin"))
            {
                return Results.Forbid();
            }

            var form = await context.Request.ReadFormAsync();
            var newUser = new UserData
            {
                Username = form["username"].ToString(),
                Email = form["email"].ToString(),
                HashedPassword = PasswordHasher.HashPassword(form["password"].ToString()),
                Role = form["role"].ToString(),
                Age = int.Parse(form["age"].ToString()),
                AppAccess = JsonSerializer.Deserialize<List<string>>(form["app_access"].ToString())!,
                PasswordLastChanged = DateTime.Now,
                PasswordExpired = true
            };

            if (string.IsNullOrEmpty(newUser.Username) || string.IsNullOrEmpty(newUser.Email))
            {
                return Results.BadRequest(new { message = "Username and email are required" });
            }

            if (users.Any(u => u.Username == newUser.Username))
            {
                return Results.Conflict(new { message = "Username already exists" });
            }

            users.Add(newUser);

            // Create a reusable JsonSerializerOptions
            var jsonOptions = new JsonSerializerOptions 
            { 
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };

            // Use these options when writing to users.json
            await File.WriteAllTextAsync(usersFilePath, 
                JsonSerializer.Serialize(users, jsonOptions));

            return Results.Ok(new { message = "User created successfully" });
        })
        .RequireAuthorization();

        // Debug endpoint
        if (app.Environment.IsDevelopment())
        {
            app.MapGet("/hash/{password}", (string password) => 
            {
                var hash = PasswordHasher.HashPassword(password);
                return Results.Ok(new { hash });
            });
        }

        // Update the file paths to be relative to the application root
        var contentRoot = Directory.GetCurrentDirectory();

        // Login page
        app.MapGet("/login", () => TypedResults.PhysicalFile(
            Path.Combine(contentRoot, "wwwroot/views/auth/login.html"), "text/html"));

        // Split into two endpoints - one for the HTML page and one for the data
        app.MapGet("/dashboard", IResult (HttpContext context) =>
        {
            if (!context.Request.Cookies.ContainsKey("auth_token"))
            {
                return TypedResults.Redirect("/login");
            }
            return TypedResults.PhysicalFile(
                Path.Combine(contentRoot, "wwwroot/views/dashboard/index.html"), "text/html");
        });

        // New endpoint for user data
        app.MapGet("/api/user-data", IResult (HttpContext context) =>
        {
            try 
            {
                var handler = new JwtSecurityTokenHandler();
                var token = context.Request.Cookies["auth_token"];
                
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = app.Configuration["Jwt:Issuer"],      // Use configuration
                    ValidAudience = app.Configuration["Jwt:Audience"],   // Use configuration
                    IssuerSigningKey = new X509SecurityKey(cert)
                };

                var claimsPrincipal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
                var username = claimsPrincipal.Identity?.Name;

                var user = users.FirstOrDefault(u => u.Username == username);
                if (user == null)
                {
                    Console.WriteLine($"User not found: {username}");
                    return TypedResults.Redirect("/login");
                }

                var userData = new
                {
                    username = user.Username,
                    firstName = user.FirstName,
                    lastName = user.LastName,
                    email = user.Email,
                    phone = user.Phone,
                    role = user.Role,
                    age = user.Age,
                    appAccess = user.AppAccess,
                    passwordLastChanged = user.PasswordLastChanged,
                    passwordExpired = user.PasswordExpired,
                    pin = user.Pin,
                    totpEnabled = user.TotpEnabled,
                    totpKey = user.TotpKey
                };

                Console.WriteLine($"Sending user data: {JsonSerializer.Serialize(userData)}");
                return TypedResults.Json(userData);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token validation error: {ex.Message}");
                return TypedResults.Text("An error occurred while validating the token.");
            }
        });

        // Add password change page
        app.MapGet("/change-password", () => TypedResults.PhysicalFile(
            Path.Combine(contentRoot, "wwwroot/views/auth/change-password.html"), "text/html"));

        // Add edit profile endpoint
        app.MapPost("/update-profile", async (HttpContext context) =>
        {
            if (!context.Request.Cookies.ContainsKey("auth_token"))
            {
                return Results.Unauthorized();
            }

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var token = context.Request.Cookies["auth_token"];
                
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = app.Configuration["Jwt:Issuer"],      // Use configuration
                    ValidAudience = app.Configuration["Jwt:Audience"],   // Use configuration
                    IssuerSigningKey = new X509SecurityKey(cert)
                };

                var claimsPrincipal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
                var username = claimsPrincipal.Identity?.Name;

                var form = await context.Request.ReadFormAsync();
                
                var user = users.FirstOrDefault(u => u.Username == username);
                if (user == null)
                {
                    return Results.NotFound();
                }

                // Update all editable fields
                user.FirstName = form["firstName"].ToString();
                user.LastName = form["lastName"].ToString();
                user.Email = form["email"].ToString();
                user.Phone = form["phone"].ToString();
                if (int.TryParse(form["age"].ToString(), out int age))
                {
                    user.Age = age;
                }
                user.Pin = form["pin"].ToString();

                // Create a reusable JsonSerializerOptions
                var jsonOptions = new JsonSerializerOptions 
                { 
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };

                // Use these options when writing to users.json
                await File.WriteAllTextAsync(usersFilePath, 
                    JsonSerializer.Serialize(users, jsonOptions));

                return Results.Ok(new { message = "Profile updated successfully" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Profile update error: {ex.Message}");
                return Results.BadRequest(new { message = "Failed to update profile" });
            }
        });

        // Add edit profile page
        app.MapGet("/profile", () => TypedResults.PhysicalFile(
            Path.Combine(contentRoot, "wwwroot/views/dashboard/profile.html"), "text/html"));

        // Add these endpoints in MapAuthEndpoints
        app.MapPost("/generate-totp-key", async (HttpContext context) =>
        {
            var username = context.User.Identity?.Name;
            if (string.IsNullOrEmpty(username))
                return Results.Unauthorized();

            var user = users.FirstOrDefault(u => u.Username == username);
            if (user == null)
                return Results.NotFound();

            var key = TotpHelper.GenerateKey();
            var qrCodeUrl = TotpHelper.GenerateQrCodeUrl(key, username, app.Configuration);

            // Update user's TOTP key
            user.TotpKey = key;
            user.TotpEnabled = true;  // Enable TOTP when generating new key
            
            // Create a reusable JsonSerializerOptions
            var jsonOptions = new JsonSerializerOptions 
            { 
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };

            // Use these options when writing to users.json
            await File.WriteAllTextAsync(usersFilePath, 
                JsonSerializer.Serialize(users, jsonOptions));

            return Results.Ok(new { key, qrCodeUrl });
        });

        app.MapPost("/verify-totp", async (HttpContext context) =>
        {
            var username = context.User.Identity?.Name;
            if (string.IsNullOrEmpty(username))
                return Results.Unauthorized();

            var form = await context.Request.ReadFormAsync();
            var code = form["code"].ToString();
            var key = form["key"].ToString();

            if (TotpHelper.ValidateCode(key, code))
            {
                var user = users.FirstOrDefault(u => u.Username == username);
                if (user != null)
                {
                    user.TotpKey = key;
                    user.TotpEnabled = true;

                    // Create a reusable JsonSerializerOptions
                    var jsonOptions = new JsonSerializerOptions 
                    { 
                        WriteIndented = true,
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                    };

                    // Use these options when writing to users.json
                    await File.WriteAllTextAsync(usersFilePath, 
                        JsonSerializer.Serialize(users, jsonOptions));

                    return Results.Ok();
                }
            }

            return Results.BadRequest();
        });

        app.MapPost("/disable-totp", async (HttpContext context) =>
        {
            var username = context.User.Identity?.Name;
            if (string.IsNullOrEmpty(username))
                return Results.Unauthorized();

            var user = users.FirstOrDefault(u => u.Username == username);
            if (user != null)
            {
                user.TotpKey = string.Empty;
                user.TotpEnabled = false;

                var jsonOptions = new JsonSerializerOptions 
                { 
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };

                await File.WriteAllTextAsync(usersFilePath, 
                    JsonSerializer.Serialize(users, jsonOptions));

                return Results.Ok();
            }

            return Results.BadRequest();
        });

        app.MapPost("/update-totp-key", async (HttpContext context) =>
        {
            var username = context.User.Identity?.Name;
            if (string.IsNullOrEmpty(username))
                return Results.Unauthorized();

            var form = await context.Request.ReadFormAsync();
            var key = form["key"].ToString();

            var user = users.FirstOrDefault(u => u.Username == username);
            if (user != null)
            {
                user.TotpKey = key;
                user.TotpEnabled = true;
                
                // Create a reusable JsonSerializerOptions
                var jsonOptions = new JsonSerializerOptions 
                { 
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };

                // Use these options when writing to users.json
                await File.WriteAllTextAsync(usersFilePath, 
                    JsonSerializer.Serialize(users, jsonOptions));
                    
                return Results.Ok();
            }

            return Results.BadRequest();
        });
    }
} 