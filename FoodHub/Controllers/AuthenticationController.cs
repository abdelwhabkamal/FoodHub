using FoodHub.Models.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using FoodHub.Models;
using FoodHub.Service.Services;
using FoodHub.Service.Models;


namespace FoodHub.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public AuthenticationController(UserManager<IdentityUser> userManager, 
            RoleManager<IdentityRole> roleManager, IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService=emailService;
        }
        [HttpPost]
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] Signup signup, string role)
        {
            // Input validation
            if (!ModelState.IsValid)
            {
                return BadRequest(new Response { Status = "Error", Message = "Invalid input data" });
            }

            // Check if the user already exists
            var userExist = await _userManager.FindByEmailAsync(signup.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "User already exists" });
            }

            // Create a new user
            var user = new IdentityUser
            {
                Email = signup.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = signup.Username,
                PhoneNumber = signup.PhoneNumber
            };

            // Check if the specified role exists
            if (await _roleManager.RoleExistsAsync(role))
            {
                // Attempt to create the user
                var result = await _userManager.CreateAsync(user, signup.Password);

                if (result.Succeeded)
                {
                    // Add the user to the specified role
                    await _userManager.AddToRoleAsync(user, role);

                    // Generate email confirmation token and send confirmation email
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
                    var message = new Message(new[] { user.Email }, "Confirmation Email Link", confirmationLink);
                    _emailService.SendEmail(message);

                    return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"User created & email sent to {user.Email} successfully" });
                }
                else
                {
                    // User creation failed, return a specific status code and error details
                    return BadRequest(new Response { Status = "Error", Message = "User creation failed"});
                }
            }
            else
            {
                return StatusCode(StatusCodes.Status501NotImplemented, new Response { Status = "ERROR", Message = "This role doesn't exist" });
            }
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user=await _userManager.FindByEmailAsync(email);
            if(user !=null)
            {
                var result = await _userManager.ConfirmEmailAsync(user,token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email Verified Successfully" });
                }
            }
            return StatusCode(StatusCodes.Status501NotImplemented,
                        new Response { Status = "ERROR", Message = "This User doesnt exist" });
        }
    }
    
}
