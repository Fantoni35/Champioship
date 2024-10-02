﻿

using Championship;
using ChampionshipWebApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Localization;

public class AccountController : Controller
{
    private readonly FootballLeagueContext _context;

    public AccountController(FootballLeagueContext context)
    {
        _context = context;
    }

    // Action for Login
    public IActionResult Login(string registrationSuccessMessage = null)
    {
        ViewBag.RegistrationSuccessMessage = registrationSuccessMessage;
        ViewData["Culture"] = HttpContext.Request.Query["culture"].ToString() ?? "en";
        return View();
    }

    // Action for Language Change
    [HttpGet]
    public IActionResult ChangeLanguage(string culture)
    {
        Response.Cookies.Append(
            CookieRequestCultureProvider.DefaultCookieName,
            CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
            new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1) }
        );

        return RedirectToAction("Login");
    }

    // POST action for Login
    [HttpPost]
    public async Task<IActionResult> Login(string username, string password)
    {
        var user = await _context.Users
                                 .FirstOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());

        if (user != null && BCrypt.Net.BCrypt.Verify(password, user.Password))
        {
            var claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Username) };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
            return RedirectToAction("Index", "Home");
        }

        ModelState.AddModelError(string.Empty, "Tentativo di login non valido.");
        ViewData["Username"] = username;
        return View();
    }

    // POST action for Logout
    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }

    // POST action for Register
    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (ModelState.IsValid)
        {
            var existingUser = await _context.Users
                                             .FirstOrDefaultAsync(u => u.Username.ToLower() == model.Username.ToLower());

            if (existingUser is not null)
            {
                ViewBag.UsernameInUseMessage = "The username is already in use. Please try again with another one.";
                ViewBag.ShowRegisterModal = true;
                return View("Login");
            }

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Password);
            var user = new User { Username = model.Username, Password = hashedPassword };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return RedirectToAction("Login", new { registrationSuccessMessage = "Registration completed successfully!" });
        }

        ViewBag.ShowRegisterModal = true;
        return View("Login");
    }
}
