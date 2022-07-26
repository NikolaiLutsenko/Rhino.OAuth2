﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Security.Claims;

namespace Rhino.MoneyKeeper.Services.RhinoOAuth
{
    public class RhinoOAuthOptions : OAuthOptions
    {
        public RhinoOAuthOptions()
        {
            CallbackPath = new PathString("/signin-rhino");
            AuthorizationEndpoint = "https://localhost:7043/OAuth/Login";
            TokenEndpoint = "https://localhost:7043/OAuth/Token";
            UserInformationEndpoint = "https://localhost:7043/OAuth/user-information";
            Scope.Add("read_profile");

            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
            ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
            //ClaimActions.MapJsonKey(ClaimTypes.GivenName, "given_name");
            //ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");
            ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            ClaimActions.MapJsonKey("scope", "scope");
        }
    }
}
