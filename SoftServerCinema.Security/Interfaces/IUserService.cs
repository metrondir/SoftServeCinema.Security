using Google.Apis.Auth;
using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.Entities;
using SoftServerCinema.Security.Services.Authentication;

namespace SoftServerCinema.Security.Interfaces
{
    public interface IUserService
    {
        Task<UserDTO> GetByIdAsync(string userId);
        Task<bool> IsUserExist(string email);
        Task<bool> Create(UserRegisterDTO userRegisterDTO);
        Task<UserDTOWithTokens> Login(UserLoginDTO userLoginDTO);
        Task<UserDTOWithTokens> SignInGoogle(UserRegisterDTO userRegister);

        Task<bool> ChangeRole(ChangeRoleDTO changeRoleDTO);
        Task<bool>LogOut(string userId);
        Task<bool> Delete(string userId);
        //email
        Task<bool> VerifyEmail(string userId, string code);

        //tokens
        Task <AuthenticatedUserResponse> VerifyAndGenerateTokens(TokenRequest tokenRequest);
        
        Task<bool> SendResetCode(string email);
        Task<bool> VerifyResetCode(ResetCodeDTO resetCodeDTO);
       
    }
}
