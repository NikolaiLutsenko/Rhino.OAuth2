namespace Rhino.Identity.Controllers
{
    public partial class OAuthController
    {
        private record CodeInfo(
            Guid Id,
            string ClientId,
            string CodeChallenge,
            string CodeChallengeMethod,
            string RedirectUrl,
            string ResponseType,
            string Scope,
            string State,
            string UserId,
            string Code)
            : LoginInfo(Id, ClientId, CodeChallenge, CodeChallengeMethod, RedirectUrl, ResponseType, Scope, State);
    }
}
