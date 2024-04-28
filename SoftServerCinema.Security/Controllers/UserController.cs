using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SoftServerCinema.Security.DTOs;
using SoftServerCinema.Security.Interfaces;
using System.ComponentModel.DataAnnotations;

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
                return BadRequest();
        }
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO userLoginDTO)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Failed model validation");
            var user = await _userService.Login(userLoginDTO);
            if (user)
                return Ok();
            else
                return BadRequest();
        }
        [AllowAnonymous]
        [HttpGet("{userId:Guid}")]
        public async Task<IActionResult> GetUserById([FromRoute] Guid userId)
        {
            if (userId == Guid.Empty)
                throw new Exception("Invalid userId");

            var user = await _userService.GetByIdAsync(userId.ToString());
            if (user != null)
                return Ok(user);
            throw new Exception("User doesn't exist");
        }


        [AllowAnonymous]
        [HttpGet("{email}")]
        public async Task<IActionResult> EmailUsed([FromRoute] string email)
        {
            var response = await _userService.IsUserExist(email);
            if (!response)
               throw new Exception("User doesn't exist");
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
    }
}
