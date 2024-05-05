using Microsoft.AspNetCore.Identity;
using SoftServerCinema.Security.DataAccess;
using SoftServerCinema.Security.Entities;
using SoftServerCinema.Security.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using Microsoft.EntityFrameworkCore;
using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.ErrorFilter;

namespace SoftServerCinema.Security.Services.Authentication
{
    public class TokenGenerator : ITokenGenerator
    {
        private const int RefreshTokenSize = 32;
        private readonly UserManager<UserEntity> _userManager;
        private readonly SecurityContext _context;
        private readonly AuthSettings _authSettings;
        public TokenGenerator(UserManager<UserEntity> userManager, AuthSettings authSettings, SecurityContext context)
        {
            _userManager = userManager;
            _authSettings = authSettings;
            _context = context;
        }

        public async Task<string> GenerateAccessToken(UserEntity user)
        {
         var handler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_authSettings.SecretKey);
            var roles = await  _userManager.GetRolesAsync(user);
            var identity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, roles.FirstOrDefault())
            });
            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = _authSettings.Issuer,
                Audience = _authSettings.Audience,
                Subject = identity,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Expires = DateTime.UtcNow.AddMinutes(_authSettings.AccessTokenExpirationMinutes),
            };
            var securityToken = handler.CreateToken(securityTokenDescriptor);
            return handler.WriteToken(securityToken);
        }

        public string GenerateRefreshToken(UserEntity user)
        {
          var randomNumber = new byte[RefreshTokenSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public async Task<AuthenticatedUserResponse> GenerateTokens(UserEntity user)
        {
           user.RefreshToken = GenerateRefreshToken(user);
           user.ExpirationTime = DateTimeOffset.UtcNow.AddDays(_authSettings.RefreshTokenExpirationDays).ToUnixTimeSeconds();
           var result = await _userManager.UpdateAsync(user);
            if(!result.Succeeded)
            {
               throw new ApiException()
               {
                   StatusCode = StatusCodes.Status500InternalServerError,
                   Title = "Can't create refresh token",
                   Detail = "Error occured while creating refresh token"
               };
            }
            return new AuthenticatedUserResponse
            {
                AccessToken = await GenerateAccessToken(user),
                RefreshToken = user.RefreshToken,
            };
        }

        public async Task<AuthenticatedUserResponse> RefreshAccessToken(TokenRequest tokenRequest)
        {
            var principal = GetPrincipalFromExpiredToken(tokenRequest.AccessToken);
            var user = await _userManager.FindByIdAsync(principal.FindFirstValue(ClaimTypes.NameIdentifier));  
            if (user == null || user.RefreshToken != tokenRequest.RefreshToken || user.ExpirationTime <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                throw new SecurityTokenException("Invalid token");
            }
            var dateNow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if(user.ExpirationTime < dateNow)
            {
                throw new SecurityTokenException("Login again");
            }
            user.RefreshToken = GenerateRefreshToken(user);
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Can't create refresh token",
                    Detail = "Error occured while creating refresh token"
                };
            }
            return new AuthenticatedUserResponse
            {
                AccessToken = await GenerateAccessToken(user),
                RefreshToken = user.RefreshToken,
            };
           
        }
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParametrs = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _authSettings.GetSecurityKey(),
                ValidateLifetime = false

            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParametrs, out _);
            return principal;
        }
    }
    
}
