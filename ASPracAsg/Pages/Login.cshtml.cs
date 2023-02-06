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

namespace ASPracAsg.Pages
{
	[ValidateReCaptcha]
	public class LoginModel : PageModel
	{
		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly UserManager<ApplicationUser> userManager;
		private readonly AuthDbContext _context;
		private readonly EmailSender _emailsender;
		private RoleManager<IdentityRole> roleManager;
		public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LoginModel> logger, AuthDbContext context, EmailSender emailSender, RoleManager<IdentityRole> roleManager)
		{
			this.signInManager = signInManager;
			this.userManager = userManager;
			_logger = logger;
			_context = context;
			_emailsender = emailSender;
			this.roleManager = roleManager;
		}
		private readonly ILogger<LoginModel> _logger;
		[BindProperty]
		public Login LModel { get; set; }
		public AuditLog AModel { get; set; } = new AuditLog();

		public async Task OnGet()
		{
			string[] roleNames = { "Administrator", "GroupUser", "User", "Guest" };
			foreach (var roleName in roleNames)
			{
				var roleExist = await roleManager.RoleExistsAsync(roleName);
				if (!roleExist)
				{
					await roleManager.CreateAsync(new IdentityRole(roleName));
				}
			}
		}
		public async Task<IActionResult> OnPostAsync()
		{
			if (ModelState.IsValid)
			{
				var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, lockoutOnFailure: true);
				if (identityResult.RequiresTwoFactor)
				{
					var user = await userManager.FindByEmailAsync(LModel.Email);
					var Token = await userManager.GenerateTwoFactorTokenAsync(user, "Email");
					var confirmation = Token;
					await _emailsender.ExecuteOTP("One-Time Password", confirmation!, user.Email);
					TempData["FlashMessage.Type"] = "success";
					TempData["FlashMessage.Text"] = string.Format("Your OTP has been sent to your email");
					return RedirectToPage("/LoginTwoStep", new { email = LModel.Email });
				}
				if (identityResult.Succeeded)
				{
					var user = await userManager.FindByEmailAsync(LModel.Email);
					await userManager.UpdateSecurityStampAsync(user);
					HttpContext.Session.SetString("UserName", LModel.Email);
					var userId = await userManager.GetUserIdAsync(user);
					await userManager.ResetAccessFailedCountAsync(user);
					//if (userId != null)
					//{
					//	AModel.userId = userId;
					//	AModel.action = "Logged In";
					//	AModel.timeStamp = DateTime.Now;
					//	_context.AuditLogs.Add(AModel);
					//	_context.SaveChanges();
					//}
					return RedirectToPage("/Index");
				}
				if (identityResult.IsLockedOut)
				{
					ModelState.AddModelError("", "The account is locked out");
					TempData["FlashMessage.Text"] = "Account is locked out, You can reset your password in Forget Password";
					TempData["FlashMessage.Type"] = "error";
					return Page();
				}
				TempData["FlashMessage.Text"] = "username or password incorrect";
				TempData["FlashMessage.Type"] = "error";
				ModelState.AddModelError("", "Username or Password incorrect");
			}
			return Page();
		}
	}
}