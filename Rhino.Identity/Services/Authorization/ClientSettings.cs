namespace Rhino.Identity.Services.Authorization
{
    public class ClientSettings
    {
        public string ClientId { get; set; } = null!;
        public string ClientSecret { get; set; } = null!;
        public string AppName { get; set; } = null!;
        public string[] Scopes { get; set; } = null!;
        public string[] AllowedRedirectUrls { get; set; } = null!;
    }
}
