using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Encodings.Web;
using ASPracAsg.Model;
using ASPracAsg.Services;
using ASPracAsg.ViewModels;

namespace ASPracAsg.Pages
{
    public class RegisterModel : PageModel
    {

        private UserManager<ApplicationUser> userManager { get; }
        private SignInManager<ApplicationUser> signInManager { get; }
        private RoleManager<IdentityRole> roleManager { get; }
        private EmailSender _emailSender;
        private readonly AuditLogService _auditLogService;

        private IWebHostEnvironment _environment;
        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, EmailSender emailSender, AuditLogService auditLogService, IWebHostEnvironment environment)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            _auditLogService = auditLogService;
            _emailSender = emailSender;
            _environment = environment;
        }

        [BindProperty]
        public Register RModel { get; set; } = new Register();

        public void OnGet(string? email)
        {
            if (!string.IsNullOrWhiteSpace(email))
            {
                RModel.Email = email;
            }
        }


        public async Task<IActionResult> OnPostAsync(string? pfp)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await userManager.FindByEmailAsync(RModel.Email);
                if (existingUser != null)
                {
                    TempData["FlashMessage.Type"] = "danger";
                    TempData["FlashMessage.Text"] = string.Format("{0} already exist", existingUser);
                    return Page();
                }

                var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                var protector = dataProtectionProvider.CreateProtector("MySecretKey");

                var user = new ApplicationUser()
                {
                    UserName = @HtmlEncoder.Default.Encode(RModel.Email),
                    Email = @HtmlEncoder.Default.Encode(RModel.Email),
                    FullName = @HtmlEncoder.Default.Encode(RModel.FullName),
                    CreditCardNo = protector.Protect(RModel.CreditCardNo),
                    Gender = @HtmlEncoder.Default.Encode(RModel.Gender),
                    MobileNo = RModel.MobileNo,
                    DeliveryAddress = @HtmlEncoder.Default.Encode(RModel.DeliveryAddress),
                    PhotoURL = "",
                    AboutMe = @HtmlEncoder.Default.Encode(RModel.AboutMe),
                    TwoFactorEnabled = true
                };

                if (RModel.Photo != null)
                {
                    if (RModel.Photo.Length > 2 * 1024 * 1024)
                    {
                        ModelState.AddModelError("Photo", "File size cannot exceed 2MB.");
                        return Page();
                    }
                    var uploadsFolder = "Uploads";
                    var imageFile = Guid.NewGuid() + Path.GetExtension(RModel.Photo.FileName);
                    var imagePath = Path.Combine(_environment.ContentRootPath, "wwwroot", uploadsFolder, imageFile);
                    using var fileStream = new FileStream(imagePath, FileMode.Create);
                    await RModel.Photo.CopyToAsync(fileStream);
                    user.PhotoURL = string.Format("/{0}/{1}", uploadsFolder, imageFile);
                }

                var result = await userManager.CreateAsync(user, RModel.Password);
                await userManager.AddToRoleAsync(user, "User");
                if (result.Succeeded)
                {
                    await _auditLogService.LogAsync(user, "This user was created");
                    var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmation = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, token }, Request.Scheme);

                    await _emailSender.Execute("Account Verfication", confirmation!, RModel.Email);
                    TempData["FlashMessage.Type"] = "success";
                    TempData["FlashMessage.Text"] = string.Format("Email has been sent for verification");
                    return Redirect("/");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

            }
            return Page();
        }
    }
}