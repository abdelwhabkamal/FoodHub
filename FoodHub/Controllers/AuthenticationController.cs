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


namespace FoodHub.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        public AuthenticationController(UserManager<IdentityUser> userManager, 
            RoleManager<IdentityRole> roleManager, IEmailService emailService, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
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
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            // Check the User
            var user=await _userManager.FindByEmailAsync(login.Email);
            if(user != null&& await _userManager.CheckPasswordAsync(user,login.Password)) {
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
                // Returning The Token
                var jwtToken=GetToken(authClaims);
                return Ok(new
                {
                    token=new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration=jwtToken.ValidTo
                }
                    );

            }
            return Unauthorized();
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
