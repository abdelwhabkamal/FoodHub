using FoodHub.Models.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using FoodHub.Models;
using FoodHub.Service.Services;
using FoodHub.Service.Models;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;
using FoodHub.Service.Models.Authentication.Login;
using FoodHub.Service.Models.Authentication.Signup;


namespace FoodHub.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        private readonly IUserManagement _user;
        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, IEmailService emailService, IConfiguration configuration, SignInManager<IdentityUser> signInManager, IUserManagement user)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _signInManager = signInManager;
            _user = user;
        }
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] Signup signup)
        {
            var tokenResponse = await _user.CreateUserWithTokenAsync(signup);
            if (tokenResponse.IsSuccessed)
            {
                await _user.AssignRoleToUserAsync(signup.Roles,tokenResponse.Response.IdentityUser);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response.Token, email = signup.Email }, Request.Scheme);
                var message = new Message(new[] { signup.Email }, "Confirmation Email Link", confirmationLink);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                               new Response { Status = "Success", Message = $"We have sent an Link to your Email: {signup.Email}" });
                
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                               new Response { Status = "Failed", Message = tokenResponse.Message });

        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email Verified Successfully" });
                }
            }
            return StatusCode(StatusCodes.Status501NotImplemented,
                        new Response { Status = "ERROR", Message = "This User doesnt exist" });
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            var loginOtpResponse = await _user.GetOtpByLoginAsync(login);

            if (loginOtpResponse.Response != null)
            {
                var user = loginOtpResponse.Response.User;

                if (user != null)
                {
                    if (user.TwoFactorEnabled)
                    {
                        // Check if the entered password is correct
                        if (await _userManager.CheckPasswordAsync(user, login.Password))
                        {
                            var token = loginOtpResponse.Response.Token;
                            var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                            _emailService.SendEmail(message);

                            return StatusCode(StatusCodes.Status200OK,
                                new Response { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });
                        }
                    }
                    else
                    {
                        // No two-factor authentication, check password directly
                        if (await _userManager.CheckPasswordAsync(user, login.Password))
                        {
                            var serviceResponse = await _user.GetJwtTokenAsync(user);
                            return Ok(serviceResponse);
                        }
                    }
                }
            }

            // If none of the conditions are met, return Unauthorized
            return Unauthorized();
        }


        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    var serviceResponse = await _user.GetJwtTokenAsync(user);
                    return Ok(serviceResponse);
                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }
        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword([Required] string email) {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var ForgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new[] { user.Email!}, "Forgot Password Link", ForgotPasswordLink);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"Password change request is sent to email {user.Email}. Please Open Your Email!" });
            }
            else
            {
                // User creation failed, return a specific status code and error details
                return BadRequest(new Response { Status = "Error", Message = "Couldn't Sent Link To Email" });
            }
        }
        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token,string email)
        {
            var model=new ResetPassword {Token= token, Email = email};
            return Ok(new
            {
                model
            });
        }
        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var ResetPasswordResult = await _userManager.ResetPasswordAsync(user,resetPassword.Token,resetPassword.Password);
                if(!ResetPasswordResult.Succeeded)
                {
                    foreach(var error in ResetPasswordResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK, new Response 
                { Status = "Success", Message = "Password has been changed" });
            }
            else
            {
                // User creation failed, return a specific status code and error details
                return BadRequest(new Response { Status = "Error", Message = "Couldn't Sent Link To Email" });
            }
        }

    }
    
}
