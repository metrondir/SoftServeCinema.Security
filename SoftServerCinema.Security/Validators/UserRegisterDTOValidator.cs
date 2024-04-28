using SoftServerCinema.Security.DTOs;
using FluentValidation;
namespace SoftServerCinema.Security.Validators
{
    public class UserRegisterDTOValidator : AbstractValidator<UserRegisterDTO>
    {
        public UserRegisterDTOValidator()
        {
            RuleFor(u => u.Email)
            .NotEmpty().WithMessage("Email is required")
            .EmailAddress(FluentValidation.Validators.EmailValidationMode.AspNetCoreCompatible).WithMessage("Email is not valid");

            RuleFor(u => u.FirstName)
                .NotEmpty()
                .WithMessage("First Name is required");
            RuleFor(u => u.LastName)
                .NotEmpty()
                .WithMessage("Last Name is required");

            RuleFor(u => u.Password)
                .NotEmpty()
                .WithMessage("Password is required");
        }
    }
}
