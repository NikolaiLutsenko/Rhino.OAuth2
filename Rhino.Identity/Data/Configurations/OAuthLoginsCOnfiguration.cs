using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Rhino.Identity.Data.Dals;

namespace Rhino.Identity.Data.Configurations
{
    public class OAuthLoginsConfiguration : IEntityTypeConfiguration<OAuthLogins>
    {
        public void Configure(EntityTypeBuilder<OAuthLogins> builder)
        {
            builder.ToTable("oauth_logins");

            builder.HasKey(x => x.Id);
            builder.Property(x => x.Code);

            builder.HasIndex(x => new { x.ClientId, x.Code });
        }
    }
}
