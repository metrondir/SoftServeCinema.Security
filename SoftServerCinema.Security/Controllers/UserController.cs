using Microsoft.AspNetCore.Mvc;
using SoftServerCinema.Security.Interfaces;

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
    }
}
