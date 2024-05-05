using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.Interfaces;
using System.ComponentModel.DataAnnotations;
using SoftServerCinema.Security.ErrorFilter;
using System.Security.Claims;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;

namespace SoftServerCinema.Security.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class UserController: ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> GetUser()
        {
            var userId = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
                return Unauthorized("User is unauthorized");
            var user = await _userService.GetByIdAsync(userId);
            if (user != null)
                return Ok(user);
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't get user",
                Detail = "Error occured while getting user from server"
            };
        }

        [AllowAnonymous]
        [HttpGet("{userId:Guid}")]
        public async Task<IActionResult> GetUserById([FromRoute] Guid userId)
        {
            if (userId == Guid.Empty)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Invalid guid",
                    Detail = "Guid is empty"
                };

            var user = await _userService.GetByIdAsync(userId.ToString());
            if (user != null)
                return Ok(user);
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't get user",
                Detail = "Error occured while getting user from server"
            };
        }
       

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] UserRegisterDTO userRegisterDTO)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Failed model validation");
            var user = await _userService.Create(userRegisterDTO);
            if (user)
                return Ok(userRegisterDTO);
            else
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "User creation failed",
                    Detail = "Error occured while creating user on server"
                };
        }
        
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO userLoginDTO)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Failed model validation");
               var userWithTokens = await _userService.Login(userLoginDTO);
            if (userWithTokens == null)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Token generation failed",
                    Detail = "Error occured while generating tokens for user"
                };
            return Ok(userWithTokens);
        }
        

        [AllowAnonymous]
        [HttpGet("{email}")]
        public async Task<IActionResult> EmailUsed([FromRoute] string email)
        {
            var response = await _userService.IsUserExist(email);
            if (!response)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "Email is not used",
                    Detail = "Email is not used, user with this email doesn't exist"
                };
            return Ok();
        }


        [AllowAnonymous]
        [HttpGet("verify-email")]
        public async Task<IActionResult> EmailConfirmation([FromQuery] string userId, [FromQuery] string code)
        {
            if (userId == null || code == null)
                throw new ValidationException("Invalid userId or code");
            if (await _userService.VerifyEmail(userId, code))
                return Redirect("https://localhost:7262/User/EmailConfirmed");
            else
                return Redirect("https://localhost:7262/User/EmailNotConfirmed");
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenRequest tokenRequest)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Failed model validation");
            var token = await _userService.VerifyAndGenerateTokens(tokenRequest);

            if (token.AccessToken ==null || token.RefreshToken == null )
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Generating tokens",
                    Detail = "Error occured while generating new tokens"
                };
            return Ok(token);
        }

        [AllowAnonymous]
        [HttpPost("reset")]
        public async Task<IActionResult> ResetCodeEmail([FromBody] EmailDTO emailDTO)
        {
           if(!await _userService.IsUserExist(emailDTO.To))
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "User doesn't exist",
                    Detail = "Email is not used, user with this email doesn't exist"
                };
           if(await _userService.SendResetCode(emailDTO.To))
                return Ok();
            else
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Sending reset code",
                    Detail = "Error occured while sending reset code"
                };
        }

        [AllowAnonymous]
        [HttpPost("verify-reset-code")]

        public async Task<IActionResult> VerifyResetCode([FromBody] ResetCodeDTO resetCodeDTO)
        {
           if(!await _userService.IsUserExist(resetCodeDTO.Email))
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "Email is not used",
                    Detail = "Email is not used, user with this email doesn't exist"
                };
           if(await _userService.VerifyResetCode(resetCodeDTO))
                return Ok();
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Reset code verification failed",
                Detail = "Error occured while verifying reset code"
            };
        }

        [Authorize]
        [HttpGet("logout")]
        public async Task<IActionResult> UserLogOut()
        {
            var userId = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Invalid guid",
                    Detail = "Guid is empty"
                };
            if (await _userService.LogOut(userId))
                    return Ok();
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't delete user",
                Detail = "Error occured while deleting user from server"
            };
        }

        [Authorize]
        [HttpDelete]
        public async Task<IActionResult> DeleteUser()
        {
            var userId = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Invalid guid",
                    Detail = "Guid is empty"
                };
            if (await _userService.Delete(userId))
                return Ok();
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't delete user",
                Detail = "Error occured while deleting user from server"
            };
        }

        [AllowAnonymous]
        [HttpPost("signin-google")]
        public async Task<IActionResult> SignInGoogle(UserRegisterDTO userRegister)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Failed model validation"); 
            var token = await _userService.SignInGoogle(userRegister);
            if (token != null)
                return Ok(token);
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Google sign in failed",
                Detail = "Error occured while signing in with google"
            };
        }

        //[Authorize(Roles ="SuperAdmin")]
        [HttpPost("change-role")]
        public async Task<IActionResult> ChangeRole([FromBody] ChangeRoleDTO changeRoleDTO)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Failed model validation");
            if (await _userService.ChangeRole(changeRoleDTO))
                return Ok();
            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Role change failed",
                Detail = "Error occured while changing user role"
            };
        }
    }
}
