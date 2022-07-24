using System.Text.Json.Serialization;

namespace Rhino.Identity.Models.OAuth
{
    public class GenerateTokenModel
    {
        [JsonPropertyName("client_id")]
        public string ClientId { get; set; } = null!;

        [JsonPropertyName("client_secret")]
        public string ClientSecret { get; set; } = null!;

        [JsonPropertyName("code")]
        public string Code { get; set; } = null!;

        [JsonPropertyName("code_verifier")]
        public string CodeVerifier { get; set; } = null!;

        [JsonPropertyName("grant_type")]
        public string GrantType { get; set; } = null!;

        [JsonPropertyName("redirect_uri")]
        public string RedirectUrl { get; set; } = null!;
    }
}
