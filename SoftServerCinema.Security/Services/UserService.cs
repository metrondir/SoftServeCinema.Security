using MailKit.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

using MimeKit;
using MimeKit.Text;
using MailKit.Net.Smtp;

using SoftServerCinema.Security.DataAccess;
using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.Entities;
using SoftServerCinema.Security.Interfaces;
using SoftServerCinema.Security.Services.Authentication.cs;


namespace SoftServerCinema.Security.Services
{
    public class UserService : IUserService
    {
        private readonly SecurityContext _context;
        private readonly UserManager<UserEntity> _userManager;
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;
        public UserService(SecurityContext context,RoleManager<IdentityRole<Guid>> roleManager, UserManager<UserEntity> userManager)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
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


        public async Task<bool> Login(UserLoginDTO userLoginDTO)
        {
            var user = await IsUserExist(userLoginDTO.Email);
            if (!user)
            {
                throw new Exception("User doesn't exist");
            }
            var isEmailConfirmed = await IsEmailConfirmed(userLoginDTO.Email);
            if(!isEmailConfirmed)
            {
                throw new Exception("Email not confirmed");
            }
            var passwordMatch = await CheckPasswords(userLoginDTO);
            if (!passwordMatch)
            {
                throw new Exception("Password doesn't match");
            }

            //generate tokens 
            //return tokens
            return true;
        }
        public async Task<bool> Create(UserRegisterDTO userRegisterDTO)
        {
            var user = await IsUserExist(userRegisterDTO.Email);
            if(user)
            {
                throw new Exception("User already exist");
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
                    throw new Exception("Email not sent");
                }
           
            }
           
                throw new Exception("User not created");
           

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
            throw new Exception("Role not added");
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


    }
}
