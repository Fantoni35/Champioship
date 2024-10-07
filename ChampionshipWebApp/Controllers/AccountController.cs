using Championship;
using ChampionshipWebApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using System.Globalization;
using System.Security.Claims;

public class AccountController : Controller
{
    private readonly FootballLeagueContext _context;

    public AccountController(FootballLeagueContext context)
    {
        _context = context;
    }

    public async Task<IActionResult> Login(string registrationSuccessMessage = null)
    {
        if (TempData["RegistrationSuccessMessage"] != null)
        {
            ViewBag.RegistrationSuccessMessage = TempData["RegistrationSuccessMessage"];
        }
        else
        {
            ViewBag.RegistrationSuccessMessage = registrationSuccessMessage;
        }

        var languages = await _context.Languages.ToListAsync();  // Recupera le lingue dal DB
        ViewBag.Languages = new SelectList(languages, "Code", "Name");

        var currentCulture = HttpContext.Request.Query["culture"].ToString() ?? "en";
        ViewData["Culture"] = currentCulture;

        return View();
    }


    [HttpPost]
    public async Task<IActionResult> ChangeLanguage(string language)
    {
        if (language == "en" || language == "it")
        {
            var identity = (ClaimsIdentity)User.Identity;
            var claim = identity.FindFirst("Language");

            if (claim != null)
            {
                identity.RemoveClaim(claim);
            }

            identity.AddClaim(new Claim("Language", language));

            var claimsPrincipal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);

            var username = User.Identity.Name;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user != null)
            {
                user.Language = language;
                await _context.SaveChangesAsync();
            }
        }

        return RedirectToAction("Index", "Home");
    }




    [HttpPost]
    public async Task<IActionResult> Login(string username, string password)
    {
        var user = await _context.Users
                                 .FirstOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());

        if (user != null && BCrypt.Net.BCrypt.Verify(password, user.Password))
        {
            var userPreferredCulture = user.Language ?? "en";

            var cultureInfo = new CultureInfo(user.Language ?? "en");
            CultureInfo.CurrentCulture = cultureInfo;
            CultureInfo.CurrentUICulture = cultureInfo;

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("Language", userPreferredCulture)
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

            return RedirectToAction("Index", "Home");
        }

        var defaultCulture = user?.Language ?? "en";
        ModelState.AddModelError(string.Empty,
            defaultCulture == "it" ? "Tentativo di login non valido." : "Invalid login attempt.");

        ViewData["Username"] = username;
        ViewData["Culture"] = defaultCulture;

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }

    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model, string culture = "en")
    {
        if (ModelState.IsValid)
        {
            var existingUser = await _context.Users
                                             .FirstOrDefaultAsync(u => u.Username.ToLower() == model.Username.ToLower());

            if (existingUser != null)
            {
                ViewBag.UsernameInUseMessage = culture == "it"
                    ? "Il nome utente è già in uso. Si prega di riprovare con un altro."
                    : "The username is already in use. Please try again with another one.";
                ViewBag.ShowRegisterModal = true;
                ViewData["Culture"] = culture;
                return View("Login");
            }

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Password);
            var user = new User
            {
                Username = model.Username,
                Password = hashedPassword,
                Language = model.Language
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            TempData["RegistrationSuccessMessage"] = culture == "it"
                ? "Registration completed successfully!"
                : "Registrazione completata con successo!";
           
            return RedirectToAction("Login", new { culture = model.Language});
        }

        ViewBag.ShowRegisterModal = true;
        ViewData["Culture"] = culture;
        return View("Login");
    }
}
