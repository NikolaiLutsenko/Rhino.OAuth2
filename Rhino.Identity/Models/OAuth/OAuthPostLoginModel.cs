using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace Rhino.Identity.Models.OAuth
{
    public class OAuthPostLoginModel
    {
        [Required]
        [HiddenInput(DisplayValue = false)]
        public Guid LoginId { get; set; }

        [Required]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; } = null!;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = null!;
    }
}
