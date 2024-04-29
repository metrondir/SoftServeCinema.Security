using FluentValidation;
using SoftServerCinema.Security.DTOs;

namespace SoftServerCinema.Security.Validators
{
    public class UserLoginDTOValidator : AbstractValidator<UserLoginDTO>
    {
        public UserLoginDTOValidator()
        {
            RuleFor(u => u.Email)
            .NotEmpty().WithMessage("Email is required")
            .NotNull().WithMessage("Email is required")
            .EmailAddress(FluentValidation.Validators.EmailValidationMode.AspNetCoreCompatible).WithMessage("Email is not valid");


            RuleFor(u => u.Password)
                .NotEmpty().WithMessage("Password is required")
                .Length(8, 20).WithMessage("Password must be between 8 and 20 characters")
                .NotNull().WithMessage("Password is required")
                .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).").WithMessage("Password must contain at least one uppercase letter, one lowercase letter, and one number");

        }
    }
}
