using System.ComponentModel.DataAnnotations;

namespace Rhino.Identity.Models.Account;

public class RegisterModel
{
    [Required]
    [DataType(DataType.EmailAddress)]
    public string Email { get; set; } = null!;

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } = null!;

    [Required]
    [Compare(nameof(Password))]
    public string RepeatPassword { get; set; } = null!;

    [Required]
    public int Age { get; set; }

    [Required]
    public string Name { get; set; } = null!;

    [Required]
    public string LastName { get; set; } = null!;
}
