using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace Rhino.Identity.Models.OAuth
{
    public class OAuthLoginModel : IValidatableObject
    {
        [FromQuery(Name = "code_challenge")]
        public string CodeChallenge { get; set; } = null!;

        [FromQuery(Name = "code_challenge_method")]
        public string CodeChallengeMethod { get; set; } = null!;

        [FromQuery(Name = "response_type")]
        public string ResponseType { get; set; } = null!;

        [FromQuery(Name = "client_id")]
        public string ClientId { get; set; } = null!;

        [FromQuery(Name = "scope")]
        public string Scope { get; set; } = null!;

        [FromQuery(Name = "redirect_uri")]
        public string RedirectUrl { get; set; } = null!;

        [FromQuery(Name = "state")]
        public string State { get; set; } = null!;

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (CodeChallengeMethod != "S256")
                yield return new ValidationResult("code_challenge_method must be 'S256'");

            if (ResponseType != "code")
                yield return new ValidationResult("response_type must be 'S256'");
        }
    }
}
