using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ASPracAsg.Model;
using ASPracAsg.Services;
using Microsoft.AspNetCore.Authorization;
using ASPracAsg.Pages;
using ASPracAsg.ViewModels;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;

namespace FreshFarmMarket.Controllers
{
	public class Account : Controller
	{
		private UserManager<ApplicationUser> _userManager { get; }

		private IWebHostEnvironment _environment;
		private EmailSender _emailsender;
		private readonly AuthDbContext _authDbContext;
		private SignInManager<ApplicationUser> signInManager { get; }

		public Account(IWebHostEnvironment environment, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, EmailSender emailsender, AuthDbContext authDbContext)
		{
			_environment = environment;
			_userManager = userManager;
			this.signInManager = signInManager;
			_emailsender = emailsender;
			_authDbContext = authDbContext;
		}
		[HttpGet]
		public async Task<IActionResult> ConfirmEmail(string userid, string token)
		{
			var user = await _userManager.FindByIdAsync(userid);
			if (user == null || token == null)
			{
				TempData["FlashMessage.Type"] = "danger";
				TempData["FlashMessage.Text"] = string.Format("Invalid Email");
				return Redirect("/Error");
			}

			var result = await _userManager.ConfirmEmailAsync(user, token);
			if (result.Succeeded)
			{
				TempData["FlashMessage.Type"] = "success";
				TempData["FlashMessage.Text"] = string.Format("User {0} have been confirmed", user.UserName);
				var userId = await _userManager.GetUserIdAsync(user);
				var userHistory = new PasswordHistory()
				{
					userId = userId,
					passwordHash = user.PasswordHash,
				};
				_authDbContext.PasswordHistories.Add(userHistory);
				_authDbContext.SaveChanges();
				return Redirect("/Login");
			}
			TempData["FlashMessage.Type"] = "danger";
			TempData["FlashMessage.Text"] = string.Format("Invalid Email");
			return Redirect("/Login");
		}
		public async Task<IActionResult> ForgetPassword(string userid, string token)
		{
			var user = await _userManager.FindByIdAsync(userid);
			if (user == null || token == null)
			{
				TempData["FlashMessage.Type"] = "danger";
				TempData["FlashMessage.Text"] = string.Format("Invalid Email");
				return Redirect("/Error");
			}
			var result = await _userManager.VerifyUserTokenAsync(user, _userManager.Options.Tokens.PasswordResetTokenProvider, "ResetPassword", token);
			if (result)
			{
				return RedirectToPage("/ForgetPassword", new { email = user.Email, token = token });
			}
			TempData["FlashMessage.Type"] = "danger";
			TempData["FlashMessage.Text"] = string.Format("Invalid Email");
			return Redirect("/Login");
		}
		public IActionResult GoogleLogin(string? returnUrl = null)
		{
            var redirectUrl = Url.Action(nameof(GoogleCallback), "Account", new { returnUrl });
			var properties = signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
			return Challenge(properties, "Google");
		}
		public async Task<IActionResult> GoogleCallback(string? returnUrl = null, string? remoteError = null)
		{
			if (remoteError != null)
			{
				return Redirect("/Login");
			}

			var info = await signInManager.GetExternalLoginInfoAsync();
			Console.WriteLine(info);
			if (info == null)
			{
				return Redirect("/Register");
			}
			// Obtain the user information
			var signInResult = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false, true);
			if (signInResult.Succeeded)
			{
				var user = await _userManager.FindByEmailAsync(info.Principal.FindFirstValue(ClaimTypes.Email));
				//AuditLog AModel = new AuditLog()
				//{
				//	userId = user.Id,
				//	action = "Logged In",
				//	timeStamp = DateTime.Now,
				//};
				//_authDbContext.AuditLogs.Add(AModel);
				_authDbContext.SaveChanges();
				HttpContext.Session.SetString("UserName", info.Principal.FindFirstValue(ClaimTypes.Email));
				return Redirect("/Index");
			}
			else
			{
				var email = info.Principal.FindFirstValue(ClaimTypes.Email);
				var name = info.Principal.FindFirstValue(ClaimTypes.Name);
				var pfp = info.Principal.FindFirstValue("image");
				var user = await _userManager.FindByEmailAsync(email);
				if (user == null)
				{
					user = new ApplicationUser
					{
						UserName = email,
						Email = email,
						PhotoURL = pfp,
						PhoneNumber = info.Principal.FindFirstValue(ClaimTypes.MobilePhone),
						DeliveryAddress = info.Principal.FindFirstValue(ClaimTypes.StreetAddress),
						PasswordAge = null,
						FullName = name,
						Gender = info.Principal.FindFirstValue(ClaimTypes.Gender)
					};
					return RedirectToPage("/Register", new { email = email, pfp = pfp });
				}
				await _userManager.AddLoginAsync(user, info);
				await signInManager.SignInAsync(user, true);
				HttpContext.Session.SetString("UserName", info.Principal.FindFirstValue(ClaimTypes.Email));
				return Redirect("/Index");

			}

			// Use the user information for your application logic

			// Redirect to the original URL
		}
	}
}