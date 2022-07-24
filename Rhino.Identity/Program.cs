using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Rhino.Identity.Data;
using Rhino.Identity.Data.Dals;
using Rhino.Identity.Services.Authentication;
using Rhino.Identity.Services.Authorization;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("Identity");
builder.Services.AddDbContext<RhinoIdentityDbContext>(options =>
    options.UseMySql(builder.Configuration.GetConnectionString("Identity"), new MySqlServerVersion(new Version(8, 0, 19))));
builder.Services.AddTransient<OAuthRepo>();

builder.Services.AddDistributedMemoryCache();

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.Configure<PasswordHasherOptions>(option =>
{
    option.IterationCount = 12000;
    option.CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3;
});

builder.Services.AddIdentity<RhinoIdentityUser, IdentityRole>(options =>
    {
        options.Password.RequireNonAlphanumeric = false;
    })
    .AddEntityFrameworkStores<RhinoIdentityDbContext>()
    .AddUserManager<UserManager<RhinoIdentityUser>>()
    .AddDefaultTokenProviders();

builder.Services.AddScoped<IJwtGenerator, JwtGenerator>();
builder.Services.AddSingleton<RsaSecurityKey>(provider =>
{
    // It's required to register the RSA key with depedency injection.
    // If you don't do this, the RSA instance will be prematurely disposed.

    RSA rsa = RSA.Create();

    rsa.ImportRSAPublicKey(
        source: Convert.FromBase64String(builder.Configuration["Jwt:Asymmetric:PublicKey"]),
        bytesRead: out int _
    );

    return new RsaSecurityKey(rsa);
});

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
        options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
    })
    .AddCookie(options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        options.SlidingExpiration = true;
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/auth/forbidden";
    })
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        SecurityKey rsa = builder.Services.BuildServiceProvider().GetRequiredService<RsaSecurityKey>();

        options.IncludeErrorDetails = true; // <- great for debugging

        // Configure the actual Bearer validation
        options.TokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = rsa,
            ValidAudience = "jwt-test",
            ValidIssuer = "jwt-test",
            RequireSignedTokens = true,
            RequireExpirationTime = true, // <- JWTs are required to have "exp" property set
            ValidateLifetime = true, // <- the "exp" will be validated
            ValidateAudience = true,
            ValidateIssuer = true,
        };
    });

builder.Services.AddAuthorization(options =>
{
    var defaultAuthorizationPolicyBuilder = new AuthorizationPolicyBuilder(IdentityConstants.ApplicationScheme);

    defaultAuthorizationPolicyBuilder = defaultAuthorizationPolicyBuilder.RequireAuthenticatedUser();

    options.DefaultPolicy = defaultAuthorizationPolicyBuilder.Build();

    options.AddPolicy(RhinoPolicyNames.ReadProfile, configurePolicy =>
    {
        configurePolicy
            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireClaim("Scopes", RhinoClaimTypes.ReadProfile);
    });

    options.AddPolicy(RhinoPolicyNames.UpdateProfile, configurePolicy =>
    {
        configurePolicy
            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireClaim("Scopes", RhinoClaimTypes.UpdateProfile);
    });
});

var clientSettings = builder.Configuration.GetSection("ClientSettings").Get<ClientSettings[]>();
builder.Services.AddSingleton(clientSettings);
builder.Services.AddTransient<ClientPermissionManager>();

builder.Services.AddHttpContextAccessor();

builder.Services.AddRazorPages();
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

//app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
