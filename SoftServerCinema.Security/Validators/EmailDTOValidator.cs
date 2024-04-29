using FluentValidation;
using SoftServerCinema.Security.DTOs;

namespace SoftServerCinema.Security.Validators
{
    public class EmailDTOValidator : AbstractValidator<EmailDTO>
    {
        public EmailDTOValidator()
        {
            RuleFor(u => u.To)
                .NotEmpty().WithMessage("To is required")
                .NotNull().WithMessage("To is required")
                .EmailAddress(FluentValidation.Validators.EmailValidationMode.AspNetCoreCompatible).WithMessage("To is not valid");

        }
    }
}
