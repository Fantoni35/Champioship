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
using System.Resources;
using System.Text.Json;


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

    private IDictionary<string, ResxForLanguage[]> PopulateResxLanguages()
    {
        Dictionary<string, ResxForLanguage[]> resx = new();
        var languages = GetLanguages();
        var resManager = new ResourceManager("ChampionshipWebApp.Resources.index", typeof(Resources).Assembly);

        foreach (var lang in languages)
        {
            var culture = CultureInfo.GetCultureInfo(lang.Code);
            ResxForLanguage[] resourcesArray = new ResxForLanguage[]
            {
            new ResxForLanguage { ElementName = "SelectLanguage", ElementValue = resManager.GetString("SelectLanguage", culture) },
            new ResxForLanguage { ElementName = "LoginTitle", ElementValue = resManager.GetString("LoginTitle", culture) },
            new ResxForLanguage { ElementName = "UsernameLabel", ElementValue = resManager.GetString("UsernameLabel", culture) },
            new ResxForLanguage { ElementName = "InsertUsername", ElementValue = resManager.GetString("InsertUsername", culture) },
            new ResxForLanguage { ElementName = "InsertPassword", ElementValue = resManager.GetString("InsertPassword", culture) },
            new ResxForLanguage { ElementName = "PasswordLabel", ElementValue = resManager.GetString("PasswordLabel", culture) },
            new ResxForLanguage { ElementName = "LoginButton", ElementValue = resManager.GetString("LoginButton", culture) },
            new ResxForLanguage { ElementName = "RegisterButton", ElementValue = resManager.GetString("RegisterButton", culture) },
            new ResxForLanguage { ElementName = "InvalidCredentialsMessage", ElementValue = resManager.GetString("InvalidCredentialsMessage", culture) },
            new ResxForLanguage { ElementName = "UsernameInUse", ElementValue = resManager.GetString("UsernameInUse", culture) },

            new ResxForLanguage { ElementName = "RegisterTitleModal", ElementValue = resManager.GetString("RegisterTitleModal", culture) },
            new ResxForLanguage { ElementName = "UsernameLabelRegister", ElementValue = resManager.GetString("UsernameLabelRegister", culture) },
            new ResxForLanguage { ElementName = "PasswordLabelRegister", ElementValue = resManager.GetString("PasswordLabelRegister", culture) },
            new ResxForLanguage { ElementName = "SelectLanguageRegister", ElementValue = resManager.GetString("SelectLanguageRegister", culture) },
            new ResxForLanguage { ElementName = "RegisterButtonModal", ElementValue = resManager.GetString("RegisterButtonModal", culture) },
            new ResxForLanguage { ElementName = "InsertUsernameRegister", ElementValue = resManager.GetString("InsertUsernameRegister", culture) },
            new ResxForLanguage { ElementName = "InsertPasswordRegister", ElementValue = resManager.GetString("InsertPasswordRegister", culture) },

            };
            // Aggiungiamo la lingua e l'array serializzato al dizionario
            resx.Add(lang.Code, resourcesArray);
        }
        return resx;
    }

    [HttpGet]
    public async Task<IActionResult> Login(string? registrationSuccessMessage = null, string culture = "en")
    {
        ViewBag.RegistrationSuccessMessage = TempData["RegistrationSuccessMessage"] ?? registrationSuccessMessage;
        ViewData["Culture"] = culture;
        ViewData["Languages"] = GetLanguages();
        ViewBag.Languages = GetLanguages();
        var resxLanguages = PopulateResxLanguages();
        ViewBag.ResxLanguages = JsonSerializer.Serialize(resxLanguages);

        if (string.IsNullOrEmpty(Request.Cookies["Culture"]))
        {
            SetCultureCookie(culture);
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
    public async Task<IActionResult> Login(string username, string password, string culture)
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
                ModelState.AddModelError(string.Empty, GetLocalizedErrorMessage(culture, "Invalid login attempt."));
            }
        }

        ViewData["Username"] = username;
        ViewData["Languages"] = GetLanguages();
        ViewData["Culture"] = culture; 
        ViewBag.ResxLanguages = JsonSerializer.Serialize(PopulateResxLanguages());
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
        if (!ModelState.IsValid)
        {
            ViewBag.ShowRegisterModal = true;
            ViewData["Languages"] = GetLanguages();
            return View("Login");
        }

        var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Username.ToLower() == model.Username.ToLower());

        if (existingUser != null)
        {
            string usernameInUseMessage = GetLocalizedErrorRegisterMessage(model.Language, "Username already in use. Try a different one.");
            ViewBag.UsernameInUseMessage = usernameInUseMessage;
            ViewBag.ShowRegisterModal = true;
            ViewData["Languages"] = GetLanguages();
            ViewData["Culture"] = model.Language;
            ViewBag.ResxLanguages = JsonSerializer.Serialize(PopulateResxLanguages());
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

    private string GetLocalizedSuccessMessage(string language, string defaultMessage)
    {
        return language switch
        {
            "it" => "Registrazione completata con successo!",
            "fr" => "Inscription réussie!",
            _ => defaultMessage
        };
    }
    private string GetLocalizedErrorRegisterMessage(string language, string defaultMessage)
    {
        return language switch
        {
            "it" => "Nome utente già in uso. Prova con un altro.",
            "fr" => "Nom d'utilisateur déjà utilisé. Essayez un autre.",
            _ => defaultMessage
        };
    }

    [HttpPost]
    public async Task<IActionResult> ChangePassword(string newPassword)
    {
        var username = User.Identity.Name;
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);

        if (user != null)
        {
            user.Password = BCrypt.Net.BCrypt.HashPassword(newPassword);
            await _context.SaveChangesAsync();
            return Json(new { success = true, message = "Password changed successfully." });
        }
        return Json(new { success = false, message = "Error during password change." });
    }

}


