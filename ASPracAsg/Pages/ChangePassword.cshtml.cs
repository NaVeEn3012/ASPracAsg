using ASPracAsg.Model;
using ASPracAsg.Services;
using ASPracAsg.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ASPracAsg.Pages
{
	[Authorize]
	public class ChangePasswordModel : PageModel
	{
		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly UserManager<ApplicationUser> userManager;
		private readonly EmailSender _emailsender;
		private readonly AuthDbContext _authDbContext;
		private readonly AuditLogService _auditLogService;
		public ChangePasswordModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, EmailSender emailSender, AuditLogService auditLogService)
		{
			this.signInManager = signInManager;
			this.userManager = userManager;
			_emailsender = emailSender;
			_auditLogService = auditLogService;
		}
		[BindProperty]
		public ChangePassword CPModel { get; set; }
		public void OnGet()
		{
		}
		public async Task<IActionResult> OnPostAsync()
		{

			if (!ModelState.IsValid)
			{
				TempData["FlashMessage.Text"] = "Passwords do not match";
				TempData["FlashMessage.Type"] = "danger";
				return Page();
			}

			var user = await userManager.GetUserAsync(User);
			if (user == null)
			{
				TempData["FlashMessage.Text"] = "Invalid Tokens";
				TempData["FlashMessage.Type"] = "danger";
				return Redirect("/");
			}

			if (DateTime.Now < user.PasswordAge.Value.AddMinutes(20))
			{
				TempData["FlashMessage.Type"] = "danger";
				TempData["FlashMessage.Text"] = "You cannot change your password as you changed it recently.";
				return Redirect("/Index");
			}
			var passwords = _authDbContext.PasswordHistories.Where(x => x.userId.Equals(user.Id)).OrderByDescending(x => x.Id).Select(x => x.passwordHash).Take(2).ToList();
			foreach (var oldpw in passwords)
			{
				if (userManager.PasswordHasher.HashPassword(user, CPModel.Password) == oldpw)
				{
					TempData["FlashMessage.Type"] = "danger";
					TempData["FlashMessage.Text"] = "Cannot use your previous 2 passwordse";
					return Page();
				}
			}
			var changePW = await userManager.ChangePasswordAsync(user, CPModel.OldPassword, CPModel.Password);
			if (changePW.Succeeded)
			{
				var newPassword = new PasswordHistory()
				{
					userId = user.Id,
					passwordHash = user.PasswordHash
				};
				_authDbContext.PasswordHistories.Add(newPassword);
				await _authDbContext.SaveChangesAsync();
				user.PasswordAge = DateTime.Now;
				await userManager.UpdateAsync(user);
				await signInManager.SignOutAsync();
				HttpContext.Session.Remove("UserName");

				await _auditLogService.LogAsync(user, "Logout");
				TempData["FlashMessage.Type"] = "Success";
				TempData["FlashMessage.Text"] = "Successfully reset password! Please login with your new password";
				return Redirect("/Login");
			}
			return Page();
		}
	}
}