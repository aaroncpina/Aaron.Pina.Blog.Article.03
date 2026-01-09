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
        ValidateIssuer = true,
        ValidIssuer = "https://localhost",
        ValidateAudience = true,
        ValidAudience = "https://localhost",
        ValidateLifetime = true,
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
    var now = DateTime.UtcNow;
    
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()),
        new Claim(JwtRegisteredClaimNames.Name, "Aaron Pina")
    };

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        IssuedAt = now,
        Expires = now.AddMinutes(30),
        Issuer = "https://localhost",
        Audience = "https://localhost",
        Subject = new ClaimsIdentity(claims),
        SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
    };

    var handler = new JwtSecurityTokenHandler();
    var token = handler.CreateToken(tokenDescriptor);

    return Results.Ok(new { Token = handler.WriteToken(token) });
}).AllowAnonymous();

app.MapGet("/protected", () => "Secret data!")
   .RequireAuthorization();

app.Run();
