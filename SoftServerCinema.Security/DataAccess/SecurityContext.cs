using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SoftServerCinema.Security.Entities;

namespace SoftServerCinema.Security.DataAccess
{
    public class SecurityContext : IdentityDbContext<UserEntity, IdentityRole<Guid>, Guid>
    {
        public SecurityContext() { }
        public SecurityContext(DbContextOptions<SecurityContext> options) : base(options) { }

       
    }

}
