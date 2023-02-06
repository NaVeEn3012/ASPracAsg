using ASPracAsg.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ASPracAsg.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        private UserManager<ApplicationUser> _userManager { get; }
        private IDataProtectionProvider _dataProtectionProvider { get; }
        private readonly SignInManager<ApplicationUser> signInManager;


        public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager, IDataProtectionProvider dataProtectionProvider, SignInManager<ApplicationUser> signInManager)
        {
            _logger = logger;
            _userManager = userManager;
            _dataProtectionProvider = dataProtectionProvider;
            this.signInManager = signInManager;

        }
        public string FullName { get; set; }
        public string CreditCardNo { get; set; }
        public string CreditCardNo_Decrypted { get; set; }
        public string Gender { get; set; }
        public int MobileNo { get; set; }
        public string DeliveryAddress { get; set; }
        public string Email { get; set; }
        public string AboutMe { get; set; }
        public string? Photo { get; set; }
        public string Password { get; set; }
        public async Task<IActionResult> OnGetAsync()
        {
            var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
            var protector = dataProtectionProvider.CreateProtector("MySecretKey");
            var user = await _userManager.GetUserAsync(User);
            {
                if (user != null)
                {
                    FullName = user.FullName;
                    CreditCardNo_Decrypted = protector.Protect(user.CreditCardNo);
                    CreditCardNo = protector.Unprotect(user.CreditCardNo);
                    Gender = user.Gender;
                    MobileNo = user.MobileNo;
                    DeliveryAddress = user.DeliveryAddress;
                    Email = user.Email;
                    AboutMe = user.AboutMe;
                    Photo = user.PhotoURL;
                    Password = user.PasswordHash;
                    return Page();
                }
                else
                {
                    return RedirectToPage("/Login");
                }
            }

        }
    }
}



