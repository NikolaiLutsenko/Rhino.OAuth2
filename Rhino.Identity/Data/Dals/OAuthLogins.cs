namespace Rhino.Identity.Data.Dals;

public class OAuthLogins
{
    public Guid Id { get; set; }

    public string CodeChallenge { get; set; } = null!;

    public string CodeChallengeMethod { get; set; } = null!;

    public string ResponseType { get; set; } = null!;

    public string ClientId { get; set; } = null!;

    public string Scopes { get; set; } = null!;

    public string RedirectUrl { get; set; } = null!;

    public string? Code { get; set; }

    public string? AuthorizationToken { get; set; }

    public string? RefreshToken { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public string? UserId { get; set; }

    public string? State { get; set; }
}
