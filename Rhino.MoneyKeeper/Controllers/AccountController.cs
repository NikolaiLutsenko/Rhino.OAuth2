using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Rhino.MoneyKeeper.Services;

namespace Rhino.MoneyKeeper.Controllers
{
    public class AccountController : Controller
    {
        private readonly RhinoOAuthService _rhinoOAuthService;

        public AccountController(RhinoOAuthService rhinoOAuthService)
        {
            _rhinoOAuthService = rhinoOAuthService;
        }

        [HttpGet]
        public async Task RhinoLogin()
        {
            var redirectUrl = Url.Action("signin-rhino");
            await this.HttpContext.ChallengeAsync("Rhino", new AuthenticationProperties
            {
                RedirectUri = redirectUrl
            });

            //var scope = "read_profile";
            //var redirectUrl = "https://localhost:7044/Account/Code";
            //
            //var codeVerifier = Guid.NewGuid().ToString();
            //
            //this.HttpContext.Session.SetString("code_verifier", codeVerifier);
            //var codeChellage = SHA256Helper.ComputeHash(codeVerifier);
            //
            //var url = _rhinoOAuthService.GenerateOAuthRequestUrl(scope, redirectUrl, codeChellage);
            //
            //return Redirect(url);
        }

        [HttpGet]
        [Authorize]
        [Route("[controller]/signin-rhino")]
        public async Task<IActionResult> RhinoResponse()
        {
            var result = await this.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        
            var claims = result.Principal.Identities
                .FirstOrDefault().Claims.Select(claim =>
                new
                {
                    claim.Issuer,
                    claim.OriginalIssuer,
                    claim.Type,
                    claim.Value
                });
        
            return Json(claims);
        }

        [HttpGet]
        public async Task<IActionResult> Code(string code)
        {
            var codeVerifier = this.HttpContext.Session.GetString("code_verifier");
            var redirectUrl = "https://localhost:7044/Account/Code";

            var tokenResult = await _rhinoOAuthService.ExchangeCodeOnTokenAsync(code, codeVerifier, redirectUrl);

            return Ok();
        }

        [HttpGet]
        public async Task<IActionResult> Test()
        {

            await _rhinoOAuthService.Test("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoiTmlrb2xhaSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2VtYWlsYWRkcmVzcyI6Imx1Y2Vua29kZXZAZ21haWwuY29tIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZGF0ZW9mYmlydGgiOiI3MjYyMjA4MDAiLCJuYmYiOjE2NTg1OTAyMjMsImV4cCI6MTY1ODU5MzgyMywiaXNzIjoiand0LXRlc3QiLCJhdWQiOiJqd3QtdGVzdCJ9.AACr0adlrFleT4it-Be-T9dYEh5pigiho4p6jA4I7s6hSRJ4CsVcr7rYf5tm0Pb7oc0DVWc66v9f0TsJFPsZYo60ACUtkYuwjOJJL_5SFMkhUVzVQkdL2YVEwK2trxW8qcmUHbrI_jZNOfkFboJ76x-2IuT5-Nv0jP0Xcpu_CFKm9wcZEH5-dhzhbSz0yyWiikA-u3QaKTm1yPGXfT0wd_O4irUHx7u1J4duq4C_68Lna1pe53wBpialt1lP7Zt_bej-lUIJmt5stb2saly94QUcKe_OSaoVROu5qLzz2XMQ48__Pcl0z5npapN5CF6o2vt6VwqCfR-o4i-ge0PN3Q");
            return Ok();
        }
    }
}
