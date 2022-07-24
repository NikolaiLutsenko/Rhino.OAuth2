using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Rhino.Identity.Data.Dals;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Rhino.Identity.Services.Authorization;

public interface IJwtGenerator
{
    Task<JwtSecurityToken> Generate(RhinoIdentityUser identityUser, string[] scopes);
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

    public async Task<JwtSecurityToken> Generate(RhinoIdentityUser identityUser, string[] scopes)
    {
        RSA rsa = RSA.Create();
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
        return new JwtSecurityToken(
            audience: "jwt-test",
            issuer: "jwt-test",
            claims: claims,
            notBefore: jwtDate,
            expires: jwtDate.AddMinutes(60),
            signingCredentials: signingCredentials
        );
    }
}
