using ASPracAsg.Model;
using ASPracAsg.Services;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ASPracAsg.Pages
{
	public class ForgetPasswordEmailModel : PageModel
	{
		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly UserManager<ApplicationUser> userManager;
		private readonly AuthDbContext _context;
		private readonly EmailSender _emailsender;
		private readonly AuthDbContext _authDbContext;
		public ForgetPasswordEmailModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext context, EmailSender emailSender, AuthDbContext authDbContext)
		{
			this.signInManager = signInManager;
			this.userManager = userManager;
			_context = context;
			_emailsender = emailSender;
			_authDbContext = authDbContext;
		}
		[BindProperty]
		public string Email { get; set; }
		public void OnGet()
		{

		}
		public async Task<IActionResult> OnPostAsync()
		{
			var user = await userManager.FindByEmailAsync(Email);
			if (user == null || !(await userManager.IsEmailConfirmedAsync(user)))
			{
				TempData["FlashMessage.Type"] = "error";
				TempData["FlashMessage.Text"] = "Email does not exist or is not verified";
				return Page();
			}
			var code = await userManager.GeneratePasswordResetTokenAsync(user);
			var callbackUrl = Url.Action("ForgetPassword", "Account", new { userid = user.Id, token = code }, protocol: Request.Scheme);
			await _emailsender.Execute("Reset Password", callbackUrl, user.Email);
			TempData["FlashMessage.Type"] = "success";
			TempData["FlashMessage.Text"] = "Reset Password link has been sent to your email";
			return Redirect("/Login");
		}
	}
}