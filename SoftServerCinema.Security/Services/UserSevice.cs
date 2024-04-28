using SoftServerCinema.Security.DataAccess;
using SoftServerCinema.Security.Entities;
using SoftServerCinema.Security.Interfaces;

namespace SoftServerCinema.Security.Services
{
    public class UserSevice : IUserService
    {
        private SecurityContext _context;
        public UserSevice(SecurityContext context)
        {
            _context = context;
        }

        public Task<UserEntity> GetByIdAsync(Guid id)
        {
            throw new NotImplementedException();
        }
    }
}
