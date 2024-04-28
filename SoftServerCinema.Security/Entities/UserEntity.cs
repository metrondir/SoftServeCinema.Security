using Microsoft.AspNetCore.Identity;

namespace SoftServerCinema.Security.Entities
{
    public class UserEntity : IdentityUser<Guid>
    {
        public string? RefreshToken { get; set; }
        public long  ExpirationTime { get; set; }
    }
}
