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
    }
}
