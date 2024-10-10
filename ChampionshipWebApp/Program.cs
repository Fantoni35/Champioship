using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Localization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Serilog;
using System.Globalization;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog for logging
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Error()
    .WriteTo.File("logs/log.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

// Configure Entity Framework with SQLite
builder.Services.AddDbContext<FootballLeagueContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("FootballLeagueDatabase")));

// Configure localization
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");

builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    var supportedCultures = new List<CultureInfo>
    {
        new CultureInfo("en"),
        new CultureInfo("it")
    };

    options.DefaultRequestCulture = new RequestCulture("en");
    options.SupportedCultures = supportedCultures;
    options.SupportedUICultures = supportedCultures;

    // Aggiungi il provider del cookie per leggere la cultura
    options.RequestCultureProviders.Insert(0, new CookieRequestCultureProvider());
});

// Add controllers with views
builder.Services.AddControllersWithViews();

// Configure cookie authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
    });

var app = builder.Build();

// Use request localization
app.UseRequestLocalization(app.Services.GetRequiredService<IOptions<RequestLocalizationOptions>>().Value);

// Configure middleware for static files, routing, authentication, and authorization
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Middleware to set culture based on user claims or cookies
app.Use(async (context, next) =>
{
    if (context.User.Identity.IsAuthenticated)
    {
        // Se l'utente è autenticato, prendi la cultura dal claim
        var preferredLanguage = context.User.FindFirst("Culture")?.Value ?? "en";
        var cultureInfo = new CultureInfo(preferredLanguage);
        CultureInfo.CurrentCulture = cultureInfo;
        CultureInfo.CurrentUICulture = cultureInfo;
    }
    else
    {
        // Se l'utente non è autenticato, prendi la cultura dal cookie
        var requestCultureFeature = context.Features.Get<IRequestCultureFeature>();
        var requestCulture = requestCultureFeature?.RequestCulture.Culture ?? new CultureInfo("en");

        CultureInfo.CurrentCulture = requestCulture;
        CultureInfo.CurrentUICulture = requestCulture;
    }

    await next.Invoke();
});

// Map controller routes
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

// Run the application
app.Run();

