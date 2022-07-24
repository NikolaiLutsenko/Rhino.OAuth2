using Microsoft.AspNetCore.WebUtilities;
using System.Net.Http.Headers;

namespace Rhino.MoneyKeeper.Services
{
    public class RhinoOAuthService
    {
        private string _clientId = "Client123";
        private string _clientSecret = "Secret123";
        private HttpClient _httpClient;

        public RhinoOAuthService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        internal string GenerateOAuthRequestUrl(string scope, string redirectUrl, string codeChellage)
        {
            var oauthEndpoint = "http://localhost:5043/OAuth/Login";

            var queryParams = new Dictionary<string, string?>
            {
                { "client_id", _clientId },
                { "redirect_uri", redirectUrl },
                { "scope", scope },
                { "code_challenge", codeChellage },
                { "code_challenge_method", "S256" },
                { "response_type", "code" }
            };

            return QueryHelpers.AddQueryString(oauthEndpoint, queryParams);
        }

        internal async Task<TokenResult?> ExchangeCodeOnTokenAsync(string code, string? codeVerifier, string redirectUrl)
        {
            var tokenEndpoint = "http://localhost:5043/OAuth/Token";

            var authParams = new Dictionary<string, string?>
            {
                { "client_id", _clientId },
                { "client_secret", _clientSecret },
                { "code", code },
                { "code_verifier", codeVerifier },
                { "grant_type", "authorization_code" },
                { "redirect_uri", redirectUrl },
            };

            var response = await _httpClient.PostAsJsonAsync(tokenEndpoint, authParams);
            var result = await response.Content.ReadFromJsonAsync<TokenResult>();

            await Test(result.AccessToken);

            return result;
        }

        internal async Task Test(string token)
        {
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = null;
            httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var secured = await httpClient.GetAsync("https://localhost:7043/OAuth/Secured");
            var securedResult = await secured.Content.ReadAsStringAsync();
        }
    }
}
