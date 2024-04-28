using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace SoftServerCinema.Security.Services.Authentication.cs
{
    public class AuthSetting
    {
        public string SecretKey { get; set; }
        public double AccessTokenExpirationMinutes { get; set; }

        public string Issuer {  get; set; }
        public string Audience {  get; set; }
        public int RefreshTokenExpirationDays { get; set; }

        public SecurityKey GetSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SecretKey));
        }
     
    }
}
