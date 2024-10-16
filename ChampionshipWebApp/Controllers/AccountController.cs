using Championship;
using ChampionshipWebApp.Resources;
using ChampionshipWebApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
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

    public List<Language> GetLanguages()
    {
        return new List<Language>
        {
            new Language { Code = "en", Name = "English" },
            new Language { Code = "it", Name = "Italiano" },
            new Language { Code = "fr", Name = "Français" } 
        };
    }

    [HttpGet]
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

        var currentCulture = HttpContext.Request.Query["culture"].ToString();

        ViewData["Culture"] = currentCulture; 
        ViewData["Languages"] = GetLanguages();
        ViewBag.Languages = GetLanguages();

        if (!string.IsNullOrEmpty(currentCulture))
        {
            Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(currentCulture))
            );
        }

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> ChangeLanguage(string language)
    {
        if (language == "en" || language == "it" || language == "fr")
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

            
            Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(language))
            );
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    public IActionResult ChangeLanguageOnLogin(string language)
    {
        if (language == "en" || language == "it" || language == "fr")
        {
            Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(language))
            );
        }

        return RedirectToAction("Login");
    }

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            ModelState.AddModelError(string.Empty, "Insert data.");
        }
        else
        {
            var user = await _context.Users
                                     .FirstOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());

            if (user != null && BCrypt.Net.BCrypt.Verify(password, user.Password))
            {
                var userPreferredCulture = user.Language; 
                if (!string.IsNullOrEmpty(userPreferredCulture))
                {
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
                }

                return RedirectToAction("Index", "Home");
            }
            else
            {
                
                string errorMessage = user?.Language switch
                {
                    "it" => "Tentativo di login non valido.",
                    "fr" => "Tentative de connexion invalide.",
                    _ => "Invalid login attempt."
                };

                ModelState.AddModelError(string.Empty, errorMessage);
            }
        }

        ViewData["Username"] = username;
        ViewData["Languages"] = GetLanguages();

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }

    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (ModelState.IsValid)
        {
            var existingUser = await _context.Users
                                             .FirstOrDefaultAsync(u => u.Username.ToLower() == model.Username.ToLower());

            if (existingUser != null)
            {
                ViewData["Languages"] = GetLanguages();

                string usernameInUseMessage = model.Language switch
                {
                    "it" => "Nome utente già in uso. Prova un altro.",
                    "fr" => "Nom d'utilisateur déjà utilisé. Essayez un autre.",
                    _ => "Username already in use. Try a different one."
                };

                ViewBag.UsernameInUseMessage = usernameInUseMessage;
                ViewBag.ShowRegisterModal = true;
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

            string registrationSuccessMessage = model.Language switch
            {
                "it" => "Registrazione completata con successo!",
                "fr" => "Inscription réussie!",
                _ => "Registration completed successfully!"
            };

            TempData["RegistrationSuccessMessage"] = registrationSuccessMessage;

            return RedirectToAction("Login", new { culture = model.Language });
        }

        ViewData["Languages"] = GetLanguages();
        ViewBag.ShowRegisterModal = true;
        return View("Login");
    }
}
