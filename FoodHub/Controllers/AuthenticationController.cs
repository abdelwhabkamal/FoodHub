using FoodHub.Models.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using FoodHub.Models;


namespace FoodHub.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        [HttpPost]
        public async Task<IActionResult> Register([FromBody]Signup signup,string role)
        {
            var userExist=await _userManager.FindByEmailAsync(signup.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "User Already exists" });
            }
            //Add New User
            IdentityUser user = new()
            {
                Email = signup.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = signup.Username,
                PhoneNumber= signup.PhoneNumber               
            };

            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, signup.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { Status = "Error", Message = "User failed to created" });
                }
                await _userManager.AddToRoleAsync(user,role);
                return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Role Added Successfully" });
            }
            else {
                return StatusCode(StatusCodes.Status501NotImplemented,
                        new Response { Status = "ERROR", Message = "This Role doesnt exist" });
            }
        }
    }
}
