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
        Task<AuthenticatedUserResponse> Login(UserLoginDTO userLoginDTO);

        Task<bool> Delete(string userId);
        //email
        Task<bool> VerifyEmail(string userId, string code);

        //tokens
        Task <AuthenticatedUserResponse> VerifyAndGenerateTokens(TokenRequest tokenRequest);
        
        Task<bool> SendResetCode(string email);
        Task<bool> VerifyResetCode(string email,string code,string newPassword);
       
    }
}
