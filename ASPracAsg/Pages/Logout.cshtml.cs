using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ASPracAsg.Model;

namespace ASPracAsg.Pages
{
	public class LogoutModel : PageModel
	{
		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly UserManager<ApplicationUser> userManager;
		private readonly AuthDbContext _context;
		public LogoutModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext context)
		{
			this.signInManager = signInManager;
			this.userManager = userManager;
			_context = context;
		}
		public AuditLog AModel { get; set; } = new AuditLog();

		public void OnGet() { }
		public async Task<IActionResult> OnPostLogoutAsync()
		{
			HttpContext.Session.Remove("Username");
			var userId = userManager.GetUserId(User);
			await signInManager.SignOutAsync();
			return RedirectToPage("Login");
		}
		public IActionResult OnPostDontLogoutAsync()
		{
			return RedirectToPage("Index");
		}
	}
}