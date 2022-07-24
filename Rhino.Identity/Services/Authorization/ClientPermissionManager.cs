namespace Rhino.Identity.Services.Authorization
{
    public class ClientPermissionManager
    {
        public ClientPermissionManager(ClientSettings[] settings)
        {
            _settings = settings;
        }

        private readonly ClientSettings[] _settings;

        public Task<ClientSettings?> GetClientWithPermissions(string clientId, string[] scopes)
        {
            var clientSetting = _settings.FirstOrDefault(x => x.ClientId == clientId && scopes.All(scope => x.Scopes.Contains(scope)));

            if (clientSetting == null)
                return Task.FromResult<ClientSettings?>(null);

            return Task.FromResult<ClientSettings?>(clientSetting);
        }
    }
}
