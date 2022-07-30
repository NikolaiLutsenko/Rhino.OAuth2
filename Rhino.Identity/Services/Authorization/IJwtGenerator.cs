using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Rhino.Identity.Data.Dals;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Rhino.Identity.Services.Authorization;

public interface IJwtGenerator
{
    Task<(string Token, DateTime ExpiresIn)> GenerateAccessToken(RhinoIdentityUser identityUser, string[] scopes);

    string GenerateRefreshToken();

    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
}

class JwtGenerator : IJwtGenerator
{
    private readonly IConfiguration configuration;
    private readonly IUserClaimsPrincipalFactory<RhinoIdentityUser> principalFactory;

    public JwtGenerator(IConfiguration configuration, IUserClaimsPrincipalFactory<RhinoIdentityUser> principalFactory)
    {
        this.configuration = configuration;
        this.principalFactory = principalFactory;
    }

    public async Task<(string Token, DateTime ExpiresIn)> GenerateAccessToken(RhinoIdentityUser identityUser, string[] scopes)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey( // Convert the loaded key from base64 to bytes.
            source: Convert.FromBase64String(configuration["Jwt:Asymmetric:PrivateKey"]), // Use the private key to sign tokens
            bytesRead: out int _); // Discard the out variable 

        var signingCredentials = new SigningCredentials(
            key: new RsaSecurityKey(rsa),
            algorithm: SecurityAlgorithms.RsaSha256 // Important to use RSA version of the SHA algo 
        )
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        var claimPrincipal = await principalFactory.CreateAsync(identityUser);
        var claims = claimPrincipal.Claims.Union(scopes.Select(scope => new Claim("Scope", scope)));


        DateTime jwtDate = DateTime.Now;
        var expiresIn = jwtDate.AddMinutes(60);

        var token = new JwtSecurityToken(
            audience: "jwt-test",
            issuer: "jwt-test",
            claims: claims,
            notBefore: jwtDate,
            expires: expiresIn,
            signingCredentials: signingCredentials
);

        return (new JwtSecurityTokenHandler().WriteToken(token), expiresIn);
    }

    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey( // Convert the loaded key from base64 to bytes.
            source: Convert.FromBase64String(configuration["Jwt:Asymmetric:PrivateKey"]), // Use the private key to sign tokens
            bytesRead: out int _); // Discard the out variable 

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new RsaSecurityKey(rsa),
            ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken securityToken;
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
        var jwtSecurityToken = securityToken as JwtSecurityToken;
        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.RsaSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");
        return principal;
    }
}
