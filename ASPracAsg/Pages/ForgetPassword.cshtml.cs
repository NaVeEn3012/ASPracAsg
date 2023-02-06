using ASPracAsg.Model;
using ASPracAsg.Services;
using ASPracAsg.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ASPracAsg.Pages
{
	public class ForgetPasswordModel : PageModel
	{
		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly UserManager<ApplicationUser> userManager;
		private readonly AuthDbContext _context;
		private readonly EmailSender _emailsender;
		private readonly AuthDbContext _authDbContext;
		public ForgetPasswordModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext context, EmailSender emailSender, AuthDbContext authDbContext)
		{
			this.signInManager = signInManager;
			this.userManager = userManager;
			_context = context;
			_emailsender = emailSender;
			_authDbContext = authDbContext;
		}
		[BindProperty]
		public ForgetPassword FPModel { get; set; }
		public void OnGet()
		{
		}
		public async Task<IActionResult> OnPostAsync(string email, string token)
		{
			var user = await userManager.FindByEmailAsync(email);
			var passwords = _authDbContext.PasswordHistories.Where(x => x.userId.Equals(user.Id)).OrderByDescending(x => x.Id).Select(x => x.passwordHash).Take(2).ToList();
			foreach (var oldpw in passwords)
			{
				var check = userManager.PasswordHasher.VerifyHashedPassword(user, oldpw, FPModel.Password);
				if (check == PasswordVerificationResult.Success)
				{
					TempData["FlashMessage.Type"] = "error";
					TempData["FlashMessage.Text"] = "You already used this password before";
					return Page();
				}
			}
			var reset = await userManager.ResetPasswordAsync(user, token, FPModel.Password);
			if (reset.Succeeded)
			{
				var newPassword = new PasswordHistory()
				{
					userId = user.Id,
					passwordHash = user.PasswordHash
				};
				_authDbContext.PasswordHistories.Add(newPassword);
				await _authDbContext.SaveChangesAsync();
				user.PasswordAge = DateTime.Now;
				await userManager.ResetAccessFailedCountAsync(user);
				await userManager.UpdateAsync(user);
				TempData["FlashMessage.Type"] = "success";
				TempData["FlashMessage.Text"] = "Password changed successfully, please login.";
				return Redirect("/Login");
			}
			TempData["FlashMessage.Type"] = "error";
			TempData["FlashMessage.Text"] = "an error occurred";
			return Page();
		}
	}
}