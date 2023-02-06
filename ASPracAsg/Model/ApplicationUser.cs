using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace ASPracAsg.Model
{
    public class ApplicationUser : IdentityUser
    {
        [PersonalData]
        [RegularExpression(@"^[A-Za-z ]+$", ErrorMessage = "Full Name can only contain alphabets")]
        public string FullName { get; set; }

        [PersonalData]
        [CreditCard]
        public string? CreditCardNo { get; set; }

        [PersonalData]
        public string? Gender { get; set; }

        [PersonalData]
        public int MobileNo { get; set; }

        [PersonalData]
        public string? DeliveryAddress { get; set; }

        [PersonalData]
        public string? PhotoURL { get; set; }

        [PersonalData]
        public string? AboutMe { get; set; }

        public DateTime? PasswordAge { get; set; } = DateTime.Now;
    }
}