using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Rhino.MoneyKeeper.Services.RhinoOAuth
{
    public class RhinoOAuthHandler : OAuthHandler<RhinoOAuthOptions>
    {
        public RhinoOAuthHandler(IOptionsMonitor<RhinoOAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(
        ClaimsIdentity identity,
        AuthenticationProperties properties,
        OAuthTokenResponse tokens)
        {
            // Get the Google user
            var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            var response = await Backchannel.SendAsync(request, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"An error occurred when retrieving Google user information ({response.StatusCode}). Please check if the authentication information is correct.");
            }
            var str = await response.Content.ReadAsStringAsync(Context.RequestAborted);
            using (var payload = JsonDocument.Parse(str))
            {
                var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, payload.RootElement);
                context.RunClaimActions();
                await Events.CreatingTicket(context);
                return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
            }
        }

        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            queryStrings.Add("client_id", Options.ClientId);
            queryStrings.Add("redirect_uri", redirectUri);
            queryStrings.Add("response_type", "code");
            

            var codeVerifier = Guid.NewGuid().ToString();
            properties.SetString("code_verifier", codeVerifier);
            var codeChellange = SHA256Helper.ComputeHash(codeVerifier);
            

            AddQueryString(queryStrings, properties, "scope", FormatScope, Options.Scope);
            queryStrings.Add("code_challenge_method", "S256");
            queryStrings.Add("code_challenge", codeChellange);

            var state = Options.StateDataFormat.Protect(properties);
            queryStrings.Add("state", state);

            var authorizationEndpoint = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings!);
            return authorizationEndpoint;
        }

        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            var @params = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            @params.Add("client_id", Options.ClientId);
            @params.Add("redirect_uri", context.RedirectUri);
            @params.Add("response_type", "code");
            @params.Add("code", context.Code);

            var codeVerifier = context.Properties.GetString("code_verifier");
            @params.Add("code_verifier", codeVerifier);
            @params.Add("grant_type", "authorization_code");

            var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            var json = JsonSerializer.Serialize(@params);
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await Backchannel.SendAsync(request, Context.RequestAborted);

            using (var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Context.RequestAborted)))
            {
                if (response.IsSuccessStatusCode)
                    return OAuthTokenResponse.Success(payload);
                else
                    return OAuthTokenResponse.Failed(new Exception(payload.ToString()));
            }
                
        }

        private static void AddQueryString<T>(
            IDictionary<string, string> queryStrings,
            AuthenticationProperties properties,
            string name,
            Func<T, string?> formatter,
            T defaultValue)
        {
            string? value;
            var parameterValue = properties.GetParameter<T>(name);
            if (parameterValue != null)
            {
                value = formatter(parameterValue);
            }
            else if (!properties.Items.TryGetValue(name, out value))
            {
                value = formatter(defaultValue);
            }

            // Remove the parameter from AuthenticationProperties so it won't be serialized into the state
            properties.Items.Remove(name);

            if (value != null)
            {
                queryStrings[name] = value;
            }
        }

        private static void AddQueryString(
            IDictionary<string, string> queryStrings,
            AuthenticationProperties properties,
            string name,
            string? defaultValue = null)
            => AddQueryString(queryStrings, properties, name, x => x, defaultValue);
    }
}
