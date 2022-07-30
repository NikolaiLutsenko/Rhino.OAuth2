using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Rhino.Identity.Data;
using Rhino.Identity.Data.Dals;
using Rhino.Identity.Models.OAuth;
using Rhino.Identity.Services;
using Rhino.Identity.Services.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace Rhino.Identity.Controllers
{
    public partial class OAuthController : Controller
    {
        private readonly IDistributedCache _distributedCache;
        private readonly UserManager<RhinoIdentityUser> _userManager;
        private readonly ClientPermissionManager _clientPermissionManager;
        private readonly OAuthRepo _oAuthRepo;

        public OAuthController(
            UserManager<RhinoIdentityUser> userManager,
            ClientPermissionManager clientPermissionManager,
            OAuthRepo oAuthRepo,
            IDistributedCache distributedCache)
        {
            _distributedCache = distributedCache;
            _userManager = userManager;
            _clientPermissionManager = clientPermissionManager;
            _oAuthRepo = oAuthRepo;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromQuery] OAuthLoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var clientSetting = await _clientPermissionManager.GetClientWithPermissions(model.ClientId, model.Scope.Split(' '));
            if (clientSetting == null)
                return BadRequest(new { Message = $"ClientId: {model.ClientId} does not have permission to the scope {model.Scope}" });

            var loginInfo = new LoginInfo(
                Guid.NewGuid(),
                model.ClientId,
                model.CodeChallenge,
                model.CodeChallengeMethod,
                model.RedirectUrl,
                model.ResponseType,
                model.Scope,
                model.State);

            await _distributedCache.SetAsync($"login:{loginInfo.Id}", Encoding.UTF8.GetBytes(JsonSerializer.Serialize(loginInfo)));

            ViewBag.AppName = clientSetting.AppName;

            return View(new OAuthPostLoginModel
            {
                LoginId = loginInfo.Id
            });
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromForm] OAuthPostLoginModel model)
        {
            var byteArray = await _distributedCache.GetAsync($"login:{model.LoginId}");
            
            var loginInfo = JsonSerializer.Deserialize<LoginInfo>(Encoding.UTF8.GetString(byteArray));

            if (byteArray == null)
            {
                ModelState.AddModelError("", "Unknown login id");
                return View(ModelState);
            }

            if (!ModelState.IsValid)
                return View(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                ModelState.AddModelError("", "Cannot find user by email and password");
                return View(model);
            }

            var code = SHA256Helper.ComputeHash(Guid.NewGuid().ToString());

            if (loginInfo == null)
            {
                ModelState.AddModelError("", "Data was broken. Try to return to your service and start login flow one more time");
                return View(ModelState);
            }
            if (loginInfo == null)
                return BadRequest("Cannot set code by login id");

            var codeInfo = new CodeInfo(
                loginInfo.Id,
                loginInfo.ClientId,
                loginInfo.CodeChallenge,
                loginInfo.CodeChallengeMethod,
                loginInfo.RedirectUrl,
                loginInfo.ResponseType,
                loginInfo.Scope,
                loginInfo.State,
                user.Id,
                code);

            await _distributedCache.SetAsync(
                $"code:{codeInfo.ClientId}_{codeInfo.Code}",
                Encoding.UTF8.GetBytes(JsonSerializer.Serialize(codeInfo)));

            await _distributedCache.RemoveAsync($"login:{model.LoginId}");

            var url = QueryHelpers.AddQueryString(loginInfo.RedirectUrl, new Dictionary<string, string?>
            {
                { "code", code },
                { "state", loginInfo.State }
            });

            return Redirect(url);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Token(
            [FromServices] IJwtGenerator jwtGenerator,
            [FromBody] GenerateTokenModel model)
        {
            var codeInfoByteArray = await _distributedCache.GetAsync($"code:{model.ClientId}_{model.Code}");

            if (codeInfoByteArray == null)
                return BadRequest("Code challenge is wrong");
            var codeInfo = JsonSerializer.Deserialize<CodeInfo>(Encoding.UTF8.GetString(codeInfoByteArray));
            if (codeInfo == null)
                return BadRequest("Code challenge is wrong");

            var computed = SHA256Helper.ComputeHash(model.CodeVerifier);
            if (codeInfo.CodeChallengeMethod != "S256" || codeInfo.CodeChallenge != computed)
                return BadRequest("Code challenge is wrong");

            var user = await _userManager.FindByIdAsync(codeInfo.UserId);
            if (user == null)
                return BadRequest("Problem with user");

            var token = await jwtGenerator.GenerateAccessToken(user, codeInfo.Scope.Split(' '));
            var refreshToken = jwtGenerator.GenerateRefreshToken();

            await _oAuthRepo.AddNewLogin(
                codeInfo.Id,
                codeInfo.UserId,
                codeInfo.ClientId,
                codeInfo.Code,
                codeInfo.CodeChallenge,
                codeInfo.CodeChallengeMethod,
                codeInfo.RedirectUrl,
                codeInfo.ResponseType,
                codeInfo.Scope,
                codeInfo.State,
                token.Token,
                refreshToken: refreshToken);

            await _distributedCache.RemoveAsync($"code:{model.ClientId}_{model.Code}");

            return Ok(new TokenResult
            {
                AccessToken = token.Token,
                ExpiresIn = new DateTimeOffset(token.ExpiresIn).ToUnixTimeSeconds(),
                TokenType = "Bearer",
                RefreshToken = refreshToken,
            });
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet]
        [Route("[controller]/user-information")]
        public IActionResult UserInformation()
        {
            return Json(new
            {
                Id = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value,
                Email = User.Claims.First(x => x.Type == ClaimTypes.Email).Value,
                Name = User.Identity.Name,
                Scope = User.Claims.Where(x => x.Type == "Scope").Select(x => x.Value).ToArray()
            });
        }
    }
}
