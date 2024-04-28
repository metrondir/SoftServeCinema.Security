using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.Entities;
using SoftServerCinema.Security.Services.Authentication.cs;

namespace SoftServerCinema.Security.Interfaces
{
    public interface IUserService
    {
        Task<UserDTO> GetByIdAsync(string userId);
        Task<bool> IsUserExist(string email);
        Task<bool> Create(UserRegisterDTO userRegisterDTO);
        Task<bool> Login(UserLoginDTO userLoginDTO);

        //email
        Task<bool> VerifyEmail(string userId, string code);

        //tokens

    }
}
