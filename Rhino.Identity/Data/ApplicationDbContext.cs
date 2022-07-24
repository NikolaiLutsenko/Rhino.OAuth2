using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Rhino.Identity.Data.Configurations;
using Rhino.Identity.Data.Dals;

namespace Rhino.Identity.Data;

public class RhinoIdentityDbContext : IdentityDbContext<RhinoIdentityUser>
{
    public DbSet<OAuthLogins> OAuthLogins { get; set; }

    public RhinoIdentityDbContext(DbContextOptions<RhinoIdentityDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfiguration(new OAuthLoginsConfiguration());
    }
}
