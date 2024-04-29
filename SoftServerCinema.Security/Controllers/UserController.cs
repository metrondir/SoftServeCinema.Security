using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.Interfaces;
using System.ComponentModel.DataAnnotations;
using SoftServerCinema.Security.ErrorFilter;
using System.Security.Claims;

namespace SoftServerCinema.Security.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class UserController: ControllerBase
    {
        private IUserService _userService;

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
                return Ok();
            else
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "User creation failed",
                    Detail = "Error occured while creating user on server"
                };
        }
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO userLoginDTO)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Failed model validation");
               var token = await _userService.Login(userLoginDTO);
            if (token == null)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Token generation failed",
                    Detail = "Error occured while generating tokens for user"
                };
            return Ok(token);
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
                return Redirect("http://localhost:7262/success");
            else
                return Redirect("http://localhost:7262/failure");
        }

        [HttpGet("refresh")]
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
    }
}
