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

    private void SetCultureCookie(string language)
    {
        Response.Cookies.Append(
            CookieRequestCultureProvider.DefaultCookieName,
            CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(language))
        );
    }

    [HttpGet]
    public async Task<IActionResult> Login(string registrationSuccessMessage = null)
    {
        ViewBag.RegistrationSuccessMessage = TempData["RegistrationSuccessMessage"] ?? registrationSuccessMessage;

        var currentCulture = HttpContext.Request.Query["culture"].ToString();
        ViewData["Culture"] = currentCulture;
        ViewData["Languages"] = GetLanguages();
        ViewBag.Languages = GetLanguages();

        if (!string.IsNullOrEmpty(currentCulture))
        {
            SetCultureCookie(currentCulture);
        }

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> ChangeLanguage(string language)
    {
        if (GetLanguages().Any(l => l.Code == language))
        {
            var identity = (ClaimsIdentity)User.Identity;
            var claim = identity.FindFirst("Language");
            if (claim != null)
            {
                identity.RemoveClaim(claim);
            }
            identity.AddClaim(new Claim("Language", language));
            await UpdateUserLanguageInDatabase(User.Identity.Name, language);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
            SetCultureCookie(language);
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    public IActionResult ChangeLanguageOnLogin(string language)
    {
        if (GetLanguages().Any(l => l.Code == language))
        {
            SetCultureCookie(language);
        }

        return RedirectToAction("Login");
    }

    private async Task UpdateUserLanguageInDatabase(string username, string language)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user != null)
        {
            user.Language = language;
            await _context.SaveChangesAsync();
        }
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
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());

            if (user != null && BCrypt.Net.BCrypt.Verify(password, user.Password))
            {
                var userPreferredCulture = user.Language ?? "en";
                SetUserCulture(userPreferredCulture, user.Username);

                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError(string.Empty, GetLocalizedErrorMessage(user?.Language, "Invalid login attempt."));
            }
        }

        ViewData["Username"] = username;
        ViewData["Languages"] = GetLanguages();

        return View();
    }

    private void SetUserCulture(string language, string username)
    {
        var cultureInfo = new CultureInfo(language);
        CultureInfo.CurrentCulture = cultureInfo;
        CultureInfo.CurrentUICulture = cultureInfo;

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, username),
            new Claim("Language", language)
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity)).Wait();

        SetCultureCookie(language);
    }

    private string GetLocalizedErrorMessage(string language, string defaultMessage)
    {
        return language switch
        {
            "it" => "Tentativo di login non valido.",
            "fr" => "Tentative de connexion invalide.",
            _ => defaultMessage
        };
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
            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Username.ToLower() == model.Username.ToLower());

            if (existingUser != null)
            {
                string usernameInUseMessage = GetLocalizedErrorMessage(model.Language, "Username already in use. Try a different one.");
                ViewBag.UsernameInUseMessage = usernameInUseMessage;
                ViewBag.ShowRegisterModal = true;
                ViewData["Languages"] = GetLanguages();
                return View("Login");
            }

            var user = new User
            {
                Username = model.Username,
                Password = BCrypt.Net.BCrypt.HashPassword(model.Password),
                Language = model.Language
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            TempData["RegistrationSuccessMessage"] = GetLocalizedSuccessMessage(model.Language, "Registration completed successfully!");
            return RedirectToAction("Login", new { culture = model.Language });
        }

        ViewBag.ShowRegisterModal = true;
        ViewData["Languages"] = GetLanguages();
        return View("Login");
    }

    private string GetLocalizedSuccessMessage(string language, string defaultMessage)
    {
        return language switch
        {
            "it" => "Registrazione completata con successo!",
            "fr" => "Inscription réussie!",
            _ => defaultMessage
        };
    }

    [HttpPost]
    public async Task<IActionResult> ChangePassword(string newPassword)
    {
        if (string.IsNullOrEmpty(newPassword))
        {
            ModelState.AddModelError(string.Empty, "La nuova password non può essere vuota.");
            return RedirectToAction("Login");
        }

        var username = User.Identity.Name;
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);

        if (user != null)
        {
            user.Password = BCrypt.Net.BCrypt.HashPassword(newPassword);
            await _context.SaveChangesAsync();
        }

        TempData["PasswordChangeSuccessMessage"] = "Password modificata con successo!";
        return RedirectToAction("Login");
    }

}