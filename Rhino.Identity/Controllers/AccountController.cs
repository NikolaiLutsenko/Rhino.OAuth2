using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Rhino.Identity.Data.Dals;
using Rhino.Identity.Models.Account;
using System.Security.Claims;

namespace Rhino.Identity.Controllers;


public class AccountController : Controller
{
    private readonly SignInManager<RhinoIdentityUser> _signInManager;
    private readonly UserManager<RhinoIdentityUser> _userManager;

    public AccountController(
        SignInManager<RhinoIdentityUser> signInManager,
        UserManager<RhinoIdentityUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Login()
    {
        return View(new LoginModel());
    }

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Login([FromForm] LoginModel model, [FromQuery(Name = "returnUrl")] string? returnUrl = null)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = await _userManager.FindByEmailAsync(model.Email);

        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            await LoginInternal(user);

            return string.IsNullOrEmpty(returnUrl)
                ? RedirectToAction("Index", "Home")
                : Redirect(returnUrl);
        }

        ModelState.AddModelError("", "Wrong login or password");
        return View(model);
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Logout([FromQuery(Name = "returnUrl")] string? returnUrl = null)
    {
        await _signInManager.SignOutAsync();

        return string.IsNullOrEmpty(returnUrl)
            ? RedirectToAction(nameof(Login))
            : Redirect(returnUrl);
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Register()
    {
        return View(new RegisterModel());
    }

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Register([FromForm] RegisterModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var userExists = await _userManager.FindByEmailAsync(model.Email);
        if (userExists != null)
        {
            ModelState.AddModelError("Email", "The email is busy");
            return View(model);
        }

        RhinoIdentityUser user = new()
        {
            Email = model.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = model.Name,
            Age = model.Age,
        };
        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            ModelState.AddModelError("", "Cannot create user");
            return View(model);
        }

        await LoginInternal(user);

        return View();
    }

    private async Task LoginInternal(RhinoIdentityUser user)
    {
        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role);

        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName ?? string.Empty));

        await _signInManager.SignInWithClaimsAsync(user, isPersistent: true, identity.Claims);
    }
}
