using System.ComponentModel.DataAnnotations;

namespace ASPracAsg.ViewModels
{
	public class ForgetPassword
	{
		[Required]
		public string UserId { get; set; }
		[Required]
		[DataType(DataType.Password)]
		public string Password { get; set; }
		[DataType(DataType.Password)]
		[Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match")]
		public DateTime ConfirmPassword { get; set; }
	}
}
