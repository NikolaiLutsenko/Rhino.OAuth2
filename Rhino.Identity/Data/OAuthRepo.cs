using Rhino.Identity.Data.Dals;

namespace Rhino.Identity.Data
{
    public class OAuthRepo
    {
        private readonly RhinoIdentityDbContext _db;

        public OAuthRepo(RhinoIdentityDbContext db)
        {
            _db = db;
        }

        public async Task AddNewLogin(
            Guid id,
            string userId,
            string clientId,
            string code,
            string codeChallenge,
            string codeChallengeMethod,
            string redirectUrl,
            string responseType,
            string scopes,
            string state,
            string authorizationToken,
            string? refreshToken)
        {
            var dal = new OAuthLogins
            {
                Id = id,
                UserId = userId,
                ClientId = clientId,
                Code = code,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                CreatedAt = DateTimeOffset.UtcNow,
                RedirectUrl = redirectUrl,
                ResponseType = responseType,
                Scopes = scopes,
                State = state,
                AuthorizationToken = authorizationToken,
                RefreshToken = refreshToken
            };
            await _db.OAuthLogins.AddAsync(dal);

            await _db.SaveChangesAsync();
        }
    }
}
