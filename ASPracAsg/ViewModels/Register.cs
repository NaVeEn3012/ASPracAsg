using System.ComponentModel.DataAnnotations;

namespace ASPracAsg.ViewModels
{
    public class Register
    {
        [Required]
        [RegularExpression(@"^[A-Za-z ]+$", ErrorMessage = "Full Name should only contain alphabets")]
        public string FullName { get; set; }

        [Required]
        [DataType(DataType.CreditCard)]
        [RegularExpression(@"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})$", ErrorMessage = "Invalid Credit Card Number")]
        public string CreditCardNo { get; set; }

        [Required]
        public string Gender { get; set; }

        [Required]
        [RegularExpression(@"^([0-9]{8,})$", ErrorMessage = "Invalid Mobile Number")]
        [DataType(DataType.PhoneNumber)]
        public int MobileNo { get; set; }

        [Required]
        public string DeliveryAddress { get; set; }

        public IFormFile? Photo { get; set; }

        [Required]
        public string AboutMe { get; set; }

        [Required]
        [RegularExpression(@"^([\w-.]+)@(([[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.)|(([\w-]+.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(]?)$", ErrorMessage = "Invalid Format for Email")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]{12,}$", ErrorMessage = "Invalid Password.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match")]
        public string ConfirmPassword { get; set; }

        public bool TwoFactorEnabled { get; set; } = true;

    }

}