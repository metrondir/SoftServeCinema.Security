﻿using MailKit.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

using MimeKit;
using MimeKit.Text;
using MailKit.Net.Smtp;

using SoftServerCinema.Security.DataAccess;
using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.Entities;
using SoftServerCinema.Security.Interfaces;
using SoftServerCinema.Security.Services.Authentication;
using SoftServerCinema.Security.ErrorFilter;


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


        public async Task<AuthenticatedUserResponse> Login(UserLoginDTO userLoginDTO)
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
            var tokens = await _tokenGenerator.GenerateTokens(user);
            return tokens;

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
                var userRole = await AddRoleToUser(createdUser);
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
            var resetCode = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callBackUrl = "https://localhost:7262/"+ "reset-password?email=" + user.Email + "&code=" + resetCode;
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

        public async Task<bool> VerifyResetCode(string email, string code, string newPassword)
        {
            code = code.Replace(" ", "+");
            var user = await _userManager.FindByEmailAsync(email);
            var result = await _userManager.ResetPasswordAsync(user, code, newPassword);
            if(result.Succeeded)
                return true;
           throw new ApiException()
           {
               StatusCode = StatusCodes.Status500InternalServerError,
               Title = "Can't reset password",
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

       
    }
        

}
