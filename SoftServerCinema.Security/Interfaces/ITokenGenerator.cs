using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.Entities;
using SoftServerCinema.Security.Services.Authentication;

namespace SoftServerCinema.Security.Interfaces
{
    public interface ITokenGenerator
    {
        Task<string> GenerateAccessToken(UserEntity user);
        string GenerateRefreshToken(UserEntity user);
        Task<AuthenticatedUserResponse> RefreshAccessToken(TokenRequest tokenRequest);
        Task<AuthenticatedUserResponse> GenerateTokens(UserEntity user);
    }
}


