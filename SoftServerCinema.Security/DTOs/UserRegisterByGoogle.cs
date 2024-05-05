namespace SoftServerCinema.Security.DTOs
{
    public class UserRegisterByGoogle
    {
        public Guid Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public bool EmailConfirmed { get; set; }
    }
}
