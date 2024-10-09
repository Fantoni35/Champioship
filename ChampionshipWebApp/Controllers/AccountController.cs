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

    //  restituisce le lingue come JSON

   
    public List<Language> GetLanguages()
    {
        return new List<Language>
    {
        new Language { Code = "en", Name = "English" },
        new Language { Code = "it", Name = "Italiano" },
        new Language { Code = "it", Name = "ItalianoCH" },
        new Language { Code = "en", Name = "EnglishUS" },
        new Language { Code = "en", Name = "EnglishAUS" },
    };
    }


    [HttpGet]
    public async Task<IActionResult> Login(string registrationSuccessMessage = null)
    {
        // Check if there is a registration success message in TempData
        if (TempData["RegistrationSuccessMessage"] != null)
        {
            ViewBag.RegistrationSuccessMessage = TempData["RegistrationSuccessMessage"];
        }
        else
        {
            ViewBag.RegistrationSuccessMessage = registrationSuccessMessage;
        }

        // Retrieve the culture from the query string or default to English
        var currentCulture = HttpContext.Request.Query["culture"].ToString() ?? "en";
        ViewData["Culture"] = currentCulture;

        // Pass the list of languages to the view
        ViewData["Languages"] = GetLanguages();

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
    public async Task<IActionResult> Login(string username, string password, string culture = "en")
    {
        var user = await _context.Users
                                 .FirstOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());

        if (user != null && BCrypt.Net.BCrypt.Verify(password, user.Password))
        {
            var userPreferredCulture = user.Language ?? culture;

            var cultureInfo = new CultureInfo(userPreferredCulture);
            CultureInfo.CurrentCulture = cultureInfo;
            CultureInfo.CurrentUICulture = cultureInfo;

            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim("Language", userPreferredCulture)
        };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

            // Redirect to the Index action in Home controller with the selected culture
            return RedirectToAction("Index", "Home", new { culture = userPreferredCulture });
        }

        var defaultCulture = user?.Language ?? culture; // Use the culture passed or default
        ModelState.AddModelError(string.Empty,
            defaultCulture == "it" ? "Tentativo di login non valido." : "Invalid login attempt.");

        ViewData["Culture"] = defaultCulture;

        // Pass the list of languages to the view again in case of error
        ViewBag.Languages = GetLanguages();

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
