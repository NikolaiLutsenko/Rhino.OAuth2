using Microsoft.AspNetCore.Identity;

namespace Rhino.Identity.Data.Dals;

public class RhinoIdentityUser : IdentityUser
{
    public int Age { get; set; }
}
