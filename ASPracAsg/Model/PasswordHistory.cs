using ASPracAsg.Model;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Reflection.Metadata;

namespace ASPracAsg.Model
{
	public class PasswordHistory
	{
		[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
		[Key]
		public int Id { get; set; }
		public string userId { get; set; } = string.Empty;
		public string passwordHash { get; set; } = string.Empty;
	}
}