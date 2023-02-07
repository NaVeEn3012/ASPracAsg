using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Reflection.Metadata;
using ASPracAsg.Model;
using ASPracAsg.ViewModels;
using AspNetCore.ReCaptcha;
using Microsoft.Extensions.Configuration.UserSecrets;
using SendGrid.Helpers.Mail;
using Newtonsoft.Json.Linq;
using ASPracAsg.Services;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace ASPracAsg.Pages
{
	[ValidateReCaptcha]
	public class LoginModel : PageModel
	{
		private RoleManager<IdentityRole> roleManager;
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly AuditLogService _auditLogService;
		private readonly EmailSender _emailsender;
		public LoginModel(RoleManager<IdentityRole> roleManager, SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuditLogService auditLogService, EmailSender emailSender)
		{
			this.roleManager = roleManager;
			this._signInManager = signInManager;
			this._userManager = userManager;
			_auditLogService = auditLogService;
			_emailsender = emailSender;
		}

		[BindProperty]
		public Login LModel { get; set; }
		public async Task OnGet()
		{
			string[] roleName = { "Administrator", "GroupUser", "User", "Guest" };
			foreach (var i in roleName)
			{
				var check = await roleManager.RoleExistsAsync(i);
				if (!check)
				{
					await roleManager.CreateAsync(new IdentityRole(i));
				}
			}
		}
		public async Task<IActionResult> OnPostAsync()
		{

			if (ModelState.IsValid)
			{
				var identityResult = await _signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, true);
				var user = await _userManager.FindByEmailAsync(LModel.Email);

				if (identityResult.Succeeded)
				{
					if (user.LastPasswordChanged.AddMonths(1).CompareTo(DateTimeOffset.UtcNow) < 0)
					{
						await _signInManager.SignOutAsync();
						var code = await _userManager.GeneratePasswordResetTokenAsync(user);
						code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
						TempData["FlashMessage.Text"] = "Your password is too old. Please change your password to continue to login";
						TempData["FlashMessage.Type"] = "warning";
						return RedirectToPage("/ForgetPassword", new { code = code, username = user.UserName });
					}

					await _userManager.UpdateSecurityStampAsync(user);
					HttpContext.Session.SetString("UserName", LModel.Email);
					var userId = await _userManager.GetUserIdAsync(user);
					await _userManager.ResetAccessFailedCountAsync(user);

					await _auditLogService.LogAsync(user, "This user has Logged in");
					await _userManager.UpdateSecurityStampAsync(user);
					return RedirectToPage("/Index");
				}

				if (identityResult.RequiresTwoFactor)
				{
					if (user.LastPasswordChanged.AddMonths(1).CompareTo(DateTimeOffset.UtcNow) < 0)
					{
						await _signInManager.SignOutAsync();
						var code = await _userManager.GeneratePasswordResetTokenAsync(user);
						code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
						TempData["FlashMessage.Text"] = "Your password is too old. Please change your password to continue to login";
						TempData["FlashMessage.Type"] = "warning";
						return RedirectToPage("/ResetPassword", new { code = code, username = user.UserName });
					}

					var Token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
					var confirmation = Token;
					await _emailsender.ExecuteOTP("One-Time Password", confirmation!, user.Email);
					TempData["FlashMessage.Type"] = "success";
					TempData["FlashMessage.Text"] = string.Format("Your One Time Password Has Been sent to your email!");
					return RedirectToPage("/LoginTwoStep", new { email = LModel.Email });
				}


				if (identityResult.IsLockedOut)
				{
					ModelState.AddModelError("", "The account is locked out");
					await _auditLogService.LogAsync(user, "This user tried to login on aa locked account");
					TempData["FlashMessage.Text"] = "Your Account is locked out!";
					TempData["FlashMessage.Type"] = "danger";
					return Page();
				}

				if (user != null)
				{
					await _auditLogService.LogAsync(user, "This user has a failed login attempt");
				}

				TempData["FlashMessage.Text"] = "Username or Password incorrect!";
				TempData["FlashMessage.Type"] = "danger";
				ModelState.AddModelError("", "Username or Password incorrect");
			}
			return Page();
		}
	}
}