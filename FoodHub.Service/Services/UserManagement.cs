using Microsoft.AspNetCore.Identity;
using FoodHub.Service.Models;
using FoodHub.Service.Models.Authentication.User;
using FoodHub.Service.Models.Authentication.Signup;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using FoodHub.Service.Models.Authentication.Login;

namespace FoodHub.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        public UserManagement(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, IEmailService emailService, SignInManager<IdentityUser> signInManager,IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles,IdentityUser user)
        {
            var assignRoles=new List<string>();
            foreach(var role in roles)
            {
                if(await _roleManager.RoleExistsAsync(role))
                {
                    if(!await _userManager.IsInRoleAsync(user, role)) 
                    { 
                    await _userManager.AddToRoleAsync(user,role);
                         assignRoles.Add(role);
                    }
                }
            }
            return new ApiResponse<List<string>> {IsSuccessed=true,StatusCode=200,Message="Roels has been assigned" ,Response=assignRoles};
        }

        public async Task<ApiResponse<UserResponse>> CreateUserWithTokenAsync(Signup signup)
        {
            var userExist = await _userManager.FindByEmailAsync(signup.Email);
            if (userExist != null)
            {
                return new ApiResponse<UserResponse> { IsSuccessed = false, StatusCode = 403, Message = "User Already Exists", };
            }
            // Create a new user
            IdentityUser user = new()
            {
                Email = signup.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = signup.Username,
                PhoneNumber = signup.PhoneNumber,
                TwoFactorEnabled = true
            };
                // Attempt to create the user
                var result = await _userManager.CreateAsync(user, signup.Password);

                if (result.Succeeded)
                {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    return new ApiResponse<UserResponse> { Response=new UserResponse() { IdentityUser=user,Token=token},IsSuccessed = true, StatusCode = 201, Message = $"User created & email sent to {user.Email} successfully", };
                }
                else
                {
                    // User creation failed, return a specific status code and error details
                    return new ApiResponse<UserResponse> { IsSuccessed = false, StatusCode = 500, Message = "User creation failed" };
                }

        }

        public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(Login login)
        {
            var user = await _userManager.FindByEmailAsync(login.Email);
            if (user != null)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, login.Password, false, true);
                if (user.TwoFactorEnabled)
                {
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    return new ApiResponse<LoginOtpResponse>
                    {
                        Response = new LoginOtpResponse()
                        {
                            User = user,
                            Token = token,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        },
                        IsSuccessed = true,
                        StatusCode = 200,
                        Message = $"OTP send to the email {user.Email}"
                    };

                }
                else
                {
                    return new ApiResponse<LoginOtpResponse>
                    {
                        Response = new LoginOtpResponse()
                        {
                            User = user,
                            Token = string.Empty,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        },
                        IsSuccessed = true,
                        StatusCode = 200,
                        Message = $"2FA is not enabled"
                    };
                }
            }
            else
            {
                return new ApiResponse<LoginOtpResponse>
                {
                    IsSuccessed = false,
                    StatusCode = 404,
                    Message = $"User doesnot exist."
                };
            }
        }

        public async Task<ApiResponse<JwtToken>> GetJwtTokenAsync(IdentityUser user)
        {
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var jwtToken = GetToken(authClaims);


            return new ApiResponse<JwtToken>
            {
                Response = new JwtToken()
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    ExpiryTokenDate = jwtToken.ValidTo
                },
                IsSuccessed = true,
                StatusCode = 200,
                Message = $"Token created"
            };
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddDays(2),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }



    }
}

