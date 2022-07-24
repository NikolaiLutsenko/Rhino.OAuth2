namespace Rhino.Identity.Controllers
{
    public partial class OAuthController
    {
        private record LoginInfo(
            Guid Id,
            string ClientId,
            string CodeChallenge,
            string CodeChallengeMethod,
            string RedirectUrl,
            string ResponseType,
            string Scope,
            string State);
    }
}
