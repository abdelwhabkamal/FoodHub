using FoodHub.Service.Models;
using FoodHub.Service.Models.Authentication.Login;
using FoodHub.Service.Models.Authentication.Signup;
using FoodHub.Service.Models.Authentication.User;
using Microsoft.AspNetCore.Identity;


namespace FoodHub.Service.Services
{
    public interface IUserManagement
    {
         Task<ApiResponse<UserResponse>> CreateUserWithTokenAsync(Signup signup);
         Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles,IdentityUser user);
         Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(Login login);
         Task<ApiResponse<JwtToken>> GetJwtTokenAsync(IdentityUser user);
    }
}
