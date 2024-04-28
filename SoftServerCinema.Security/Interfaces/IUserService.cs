using SoftServerCinema.Security.Entities;

namespace SoftServerCinema.Security.Interfaces
{
    public interface IUserService
    {
        Task<UserEntity> GetByIdAsync(Guid id);
    }
}
