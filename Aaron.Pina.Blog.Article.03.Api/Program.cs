using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Claims;

using var rsa = RSA.Create(2048);
var rsaKey = new RsaSecurityKey(rsa);
var rsaPublicKey = new RsaSecurityKey(rsa.ExportParameters(false));

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidIssuer = "https://localhost:5001",
        ValidateAudience = false,
        ValidAudience = "https://localhost:5001",
        ValidateLifetime = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = rsaPublicKey,
        ClockSkew = TimeSpan.FromMinutes(5)
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/login", () =>
{
    var now = DateTimeOffset.UtcNow;
    
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()),
        new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString()),
        new Claim(JwtRegisteredClaimNames.Name, "Aaron Pina")
    };

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Issuer = "https://localhost:5001",
        Audience = "https://localhost:5001",
        Subject = new ClaimsIdentity(claims),
        Expires = now.AddMinutes(30).DateTime,
        SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
    };

    var handler = new JwtSecurityTokenHandler();
    var token = handler.CreateToken(tokenDescriptor);

    return Results.Ok(new { Token = handler.WriteToken(token) });
}).AllowAnonymous();

app.MapGet("/protected", () => "Secret data!")
   .RequireAuthorization();

app.Run();
