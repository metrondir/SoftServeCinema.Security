namespace SoftServerCinema.Security.DTOs
{
    public class ResetCodeDTO
    {
        public string ResetToken { get; set; }
        public string Email { get; set; }   
        public string Password { get; set; }

    }
}
