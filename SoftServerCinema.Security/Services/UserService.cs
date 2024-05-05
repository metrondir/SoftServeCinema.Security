using MailKit.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

using MimeKit;
using MimeKit.Text;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Authentication;

using SoftServerCinema.Security.DataAccess;
using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.Entities;
using SoftServerCinema.Security.Interfaces;
using SoftServerCinema.Security.Services.Authentication;
using SoftServerCinema.Security.ErrorFilter;
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2.Flows;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;


using Microsoft.AspNetCore.Authentication.Cookies;

namespace SoftServerCinema.Security.Services
{
    public class UserService : IUserService
    {
        private readonly SecurityContext _context;
        private readonly UserManager<UserEntity> _userManager;
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;
        private readonly ITokenGenerator _tokenGenerator;
        public UserService(SecurityContext context,RoleManager<IdentityRole<Guid>> roleManager, UserManager<UserEntity> userManager, ITokenGenerator tokenGenerator)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
            _tokenGenerator = tokenGenerator;
        }

        public async Task<UserDTO> GetByIdAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var userRole = await _userManager.GetRolesAsync(user);
            var userDto = new UserDTO()
            {
                UserName = user.UserName,
                Email = user.Email,
                Role = userRole.FirstOrDefault()
            };

                return userDto;
        }


        public async Task<UserDTOWithTokens> Login(UserLoginDTO userLoginDTO)
        {
            var user = await _userManager.FindByEmailAsync(userLoginDTO.Email);
            if (user == null)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "User doesn't exist",
                    Detail = "User doesn't exist while creating user"
                };
            }
            var isEmailConfirmed = await IsEmailConfirmed(userLoginDTO.Email);
            if (!isEmailConfirmed)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Email is not confirmed",
                    Detail = "User email is not confirmed"
                };

            }
            var passwordMatch = await CheckPasswords(userLoginDTO);
            if (!passwordMatch)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Wrong password",
                    Detail = "Password doesn't match"
                };
            }
           
            var token = await _tokenGenerator.GenerateTokens(user);
            if(token == null)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Can't generate tokens",
                    Detail = "Error occured while generating tokens"
                };
            }
            var userWithTokens = new UserDTOWithTokens()
            {
                Id = user.Id,
                FirstName = user.UserName,
                LastName = user.UserName,
                Email = user.Email,
                Role = (await _userManager.GetRolesAsync(user)).FirstOrDefault(),
                AccessToken = token.AccessToken,
                RefreshToken = token.RefreshToken
            };
            return userWithTokens;

        }
        public async Task<bool> LogOut(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "User doesn't exist",
                    Detail = "User doesn't exist while logging out"
                };
            }
            user.RefreshToken = null;
            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
                return true;
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't log out",
                Detail = "Error occured while logging out"
            };
        }
      

        public async Task<bool> Create(UserRegisterDTO userRegisterDTO)
        {
            var user = await IsUserExist(userRegisterDTO.Email);
            if(user)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Email is already used!",
                    Detail = "Email is already used! Try different one"
                };
            }
            var createdResult = await CreateUser(userRegisterDTO);
            if (createdResult)
            {
                var createdUser = await _userManager.FindByEmailAsync(userRegisterDTO.Email);
                 await AddRoleToUser(createdUser);
                var isEmailSent = await SendEmail(createdUser);
                if (isEmailSent)
                {
                    return isEmailSent;
                }
                else
                {
                    await _userManager.DeleteAsync(createdUser);
                    throw new ApiException()
                    {
                        StatusCode = StatusCodes.Status500InternalServerError,
                        Title = "Can't send email",
                        Detail = "Error occured while sending email. Deleting user"
                    };
                }
           
            }

            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't creating user",
                Detail = "Error occured while creating user on server"
            };


        }
        private async Task<bool> CreateUser(UserRegisterDTO userRegisterDTO)
        {
            var user = new UserEntity()
            {
                Email = userRegisterDTO.Email,
                UserName = userRegisterDTO.Email,
            };
            var result = await _userManager.CreateAsync(user, userRegisterDTO.Password);
            if(result.Succeeded == false)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = string.Join(",", result.Errors.Select(error => error.Description)),
                    Detail = "Error occured while creating user"
                };
            }
            return result.Succeeded;
        }

        private async Task<bool> SendEmail(UserEntity user)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = CallbackUrl(user.Id, code);
            try
            {
                var email = new MimeMessage();
                email.From.Add(MailboxAddress.Parse("kinosvet.cinema.ltd@gmail.com"));
               
                email.To.Add(MailboxAddress.Parse(user.Email));
                email.Subject = "Email Verification";
                email.Body = new TextPart(MimeKit.Text.TextFormat.Html)
                {
                    Text = $"<a href='{callbackUrl}'>Click here to verify your email</a>"
                };
                using var smtp = new SmtpClient();
                await smtp.ConnectAsync("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
              
                await smtp.AuthenticateAsync("kinosvet.cinema.ltd@gmail.com", "xmjl pygd kosx woyh");
                await smtp.SendAsync(email);
                await smtp.DisconnectAsync(true);


                return true;
            }
            catch (Exception )
            {
                return false;
            }
        }


        private string CallbackUrl(Guid userId, string code)
        {
            var ngrok = ConstantVariable.ngrok;
            var callbackUrl = $"{ngrok}/api/User/verify-email?userId={userId.ToString()}&code={code}";
            return callbackUrl;
        }
       
        private async Task<string> AddRoleToUser(UserEntity user)
        {
            var result = await _userManager.AddToRoleAsync(user, "User");
            if (result.Succeeded)
            {
                var role = await _userManager.GetRolesAsync(user);
                return role.First();
            }
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't add role to user",
                Detail = "Error occured while adding role to user"
            };
        }
       
        public async Task<bool> IsUserExist(string email)
        {
            return await _userManager.FindByEmailAsync(email) != null;
        }
        public async Task<bool> VerifyEmail(string userId, string code)
        {
            code = code.Replace(" ", "+");
            var user = await _userManager.FindByIdAsync(userId);
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return result.Succeeded;
        }
        public async Task<bool> IsEmailConfirmed(string email)
        {
            return (await _userManager.FindByEmailAsync(email)).EmailConfirmed;
        }
        public async Task<bool> CheckPasswords(UserLoginDTO userLoginDTO)
        {
            var user = await _userManager.FindByEmailAsync(userLoginDTO.Email);
            return await _userManager.CheckPasswordAsync(user, userLoginDTO.Password);
        }

        public async Task<AuthenticatedUserResponse> VerifyAndGenerateTokens(TokenRequest tokenRequest)
        {
            return await _tokenGenerator.RefreshAccessToken(tokenRequest);
        }

        public async Task<bool> SendResetCode(string emailDto)
        {
            var user = await _userManager.FindByEmailAsync(emailDto);
            if (user == null)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "User doesn't exist",
                    Detail = "User doesn't exist while verifying reset code"
                };

            if (user.EmailConfirmed == false)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Email is not confirmed",
                    Detail = "User email is not confirmed"
                };
            }
            var resetCode = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callBackUrl = "https://localhost:7262/User/"+ "ResetPassword?email=" + user.Email + "&code=" + resetCode;
            try
            {
                var email = new MimeMessage();
                email.From.Add(MailboxAddress.Parse("kinosvet.cinema.ltd@gmail.com"));
                email.To.Add(MailboxAddress.Parse(user.Email));
                email.Subject = "Password Reset";
                email.Body = new TextPart(MimeKit.Text.TextFormat.Html)
                {
                    Text = $"<a href='{callBackUrl}'>Click here to reset your password</a>"
                };
                using var smtp = new SmtpClient();
                await smtp.ConnectAsync("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
                await smtp.AuthenticateAsync("kinosvet.cinema.ltd@gmail.com", "xmjl pygd kosx woyh");
                await smtp.SendAsync(email);
                await smtp.DisconnectAsync(true);
                return true;
            }
            catch(Exception)
            {
                return false;
            }
        }

        public async Task<bool> VerifyResetCode(ResetCodeDTO resetCodeDTO)
        {
            var user = await _userManager.FindByEmailAsync(resetCodeDTO.Email);
            
            resetCodeDTO.ResetToken = resetCodeDTO.ResetToken.Replace(" ", "+");
            
            var result = await _userManager.ResetPasswordAsync(user, resetCodeDTO.ResetToken, resetCodeDTO.NewPassword);
            if(result.Succeeded)
                return true;
           throw new ApiException()
           {
               StatusCode = StatusCodes.Status400BadRequest,
               Title = string.Join(",", result.Errors.Select(error => error.Description)),
               Detail = "Error occured while resetting password"
           };
        }
         public async Task<bool> Delete(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "User doesn't exist",
                    Detail = "User doesn't exist while deleting user"
                };
            }
            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
                return true;
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't delete user",
                Detail = "Error occured while deleting user"
            };
        }
        public async Task<UserDTOWithTokens> SignInGoogle(UserRegisterDTO userRegister)
        {
            if (await IsUserExist(userRegister.Email))
            {
                var existedUser = await _userManager.FindByEmailAsync(userRegister.Email);
                var tokenExistedUser = await _tokenGenerator.GenerateTokens(existedUser);
                var existedUserWithTokens = new UserDTOWithTokens()
                {
                    Id = existedUser.Id,
                    FirstName = existedUser.UserName,
                    LastName = existedUser.UserName,
                    Email = existedUser.Email,
                    Role = (await _userManager.GetRolesAsync(existedUser)).FirstOrDefault(),
                    AccessToken = tokenExistedUser.AccessToken,
                    RefreshToken = tokenExistedUser.RefreshToken
                };
                return existedUserWithTokens;
            }
            var user = new UserEntity()
            {
                Email = userRegister.Email,
                UserName = userRegister.Email,
            };
            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded == false)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Can't create user",
                    Detail = "Error occured while creating user"
                };
            }
            var createdUser = await _userManager.FindByEmailAsync(userRegister.Email);
            await AddRoleToUser(createdUser);
            await _userManager.ConfirmEmailAsync(createdUser, await _userManager.GenerateEmailConfirmationTokenAsync(createdUser));

            var token = await _tokenGenerator.GenerateTokens(createdUser);
            if (token == null)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Can't generate tokens",
                    Detail = "Error occured while generating tokens"
                };
            }
            var userWithTokens = new UserDTOWithTokens()
            {
                Id = createdUser.Id,
                FirstName = createdUser.UserName,
                LastName = createdUser.UserName,
                Email = createdUser.Email,
                Role = (await _userManager.GetRolesAsync(createdUser)).FirstOrDefault(),
                AccessToken = token.AccessToken,
                RefreshToken = token.RefreshToken
            };
            
            return userWithTokens;

        }
        public async Task<bool> ChangeRole(ChangeRoleDTO changeRoleDTO)
        {
            var user = await _userManager.FindByEmailAsync(changeRoleDTO.Email);
            if (string.IsNullOrEmpty(user.Email))
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "User doesn't exist",
                    Detail = "User doesn't exist while changing role"
                };
            }
            var result = await _userManager.AddToRoleAsync(user, changeRoleDTO.Role);
            if (result.Succeeded)
                return true;
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't change role",
                Detail = "Error occured while changing role"
            };

        }
       }


    }




