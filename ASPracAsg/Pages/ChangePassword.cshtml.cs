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
		private readonly AuthDbContext _context;
		private readonly EmailSender _emailsender;
		private readonly AuthDbContext _authDbContext;
		public ChangePasswordModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LoginModel> logger, AuthDbContext context, EmailSender emailSender, AuthDbContext authDbContext)
		{
			this.signInManager = signInManager;
			this.userManager = userManager;
			_logger = logger;
			_context = context;
			_emailsender = emailSender;
			_authDbContext = authDbContext;
		}
		private readonly ILogger<LoginModel> _logger;
		[BindProperty]
		public ChangePassword CPModel { get; set; }
		public void OnGet()
		{
		}
		public async Task<IActionResult> OnPostAsync()
		{
			var user = await userManager.GetUserAsync(User);
			if (DateTime.Now < user.PasswordAge.Value.AddMinutes(20))
			{
				TempData["FlashMessage.Type"] = "danger";
				TempData["FlashMessage.Text"] = "You cannot change your password as you changes it recently.";
				return Redirect("/Index");
			}
			var passwords = _authDbContext.PasswordHistories.Where(x => x.userId.Equals(user.Id)).OrderByDescending(x => x.Id).Select(x => x.passwordHash).Take(2).ToList();
			foreach (var oldpw in passwords)
			{
				if (userManager.PasswordHasher.HashPassword(user, CPModel.Password) == oldpw)
				{
					TempData["FlashMessage.Type"] = "danger";
					TempData["FlashMessage.Text"] = "You already used this password before";
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
				TempData["FlashMessage.Type"] = "Success";
				TempData["FlashMessage.Text"] = "Password changed successfully, please login.";
				return Redirect("/Login");
			}
			return Page();
		}
	}
}