using System.ComponentModel.DataAnnotations;

namespace FoodHub.Models.Authentication
{
    public class ResetPassword
    {
        [Required(ErrorMessage = "Email address is required.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters.")]
        public string Password { get; set; }
        [Compare("Password",ErrorMessage="Password Doesnt Match")]
        public string ConfirmPassword { get; set; }
        public string Token { get; set; }

    }
}
