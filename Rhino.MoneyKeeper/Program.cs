using Microsoft.AspNetCore.Authentication.Cookies;
using Rhino.MoneyKeeper.Services;
using Rhino.MoneyKeeper.Services.RhinoOAuth;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddHttpClient<RhinoOAuthService>();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = "Rhino";
    })
    .AddCookie()
    .AddOAuth<RhinoOAuthOptions, RhinoOAuthHandler>("Rhino", options =>
    {
        options.ClientId = builder.Configuration["Authorization:Rhino:ClientId"];
        options.ClientSecret = builder.Configuration["Authorization:Rhino:ClientSecret"];
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
