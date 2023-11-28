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
        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, IEmailService emailService, IConfiguration configuration, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _signInManager = signInManager;
        }
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
                PhoneNumber = signup.PhoneNumber,
                TwoFactorEnabled = true
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
                    return BadRequest(new Response { Status = "Error", Message = "User creation failed" });
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
            // Check the User
            var user = await _userManager.FindByEmailAsync(login.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, login.Password)) {
                // ClaimList Creation
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Email,user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                };
                // Add Roles to List
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }
                if (user.TwoFactorEnabled)
                {
                    await _signInManager.SignOutAsync();
                    await _signInManager.PasswordSignInAsync(user, login.Password, false, true);
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    var message = new Message(new[] { user.Email }, "OTP Confirmation", token);
                    _emailService.SendEmail(message);
                    return StatusCode(StatusCodes.Status200OK,
                           new Response { Status = "Success", Message = $"We have sent an OTP to yout Email {user.Email}" });
                }
                // Returning The Token
                var jwtToken = GetToken(authClaims);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo
                }
                    );

            }
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
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Email,user.Email),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    };
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles) {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }
                    var JwtToken = GetToken(authClaims);
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(JwtToken),
                        expiration = JwtToken.ValidTo
                    });

                }
            }
            return StatusCode(StatusCodes.Status501NotImplemented,
                                       new Response { Status = "Error", Message = "Inavlid Code" });
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

        // Generate the Token with Claim
        private JwtSecurityToken GetToken(List<Claim> claims)
        {
            var authsignkey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims:claims,
                signingCredentials:new SigningCredentials(authsignkey,SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
    }
    
}
