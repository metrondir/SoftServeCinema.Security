using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Formatters;
using System.ComponentModel.DataAnnotations;
using System.Security.Authentication;
using Microsoft.AspNetCore.Mvc.Formatters;
namespace SoftServerCinema.Security.ErrorFilter
{
    public class GlobalExceptionFilter : IExceptionFilter
    {
        private readonly ILogger<GlobalExceptionFilter> _logger;
        public GlobalExceptionFilter(ILogger<GlobalExceptionFilter> logger)
        {
            _logger = logger;
        }
        public void OnException(ExceptionContext context)
        {
            var statusCode = context.Exception switch
            {
                ApiException apiException => apiException.StatusCode,
                ArgumentNullException _ => StatusCodes.Status422UnprocessableEntity,
                ValidationException _ => StatusCodes.Status422UnprocessableEntity,
                AuthenticationException _ => StatusCodes.Status401Unauthorized,
                _ => StatusCodes.Status500InternalServerError
            };
            var title = context.Exception switch
            {
                ApiException apiException => apiException.Title,
                ArgumentNullException _ => "Argument Null Exception",
                ValidationException _ => "Validation Exception",
                AuthenticationException _ => "Authentication issue",
                _ => "Internal Server Error"
            };
            var detail = context.Exception switch
            {
                ApiException apiException => apiException.Detail,
                ArgumentNullException _ => context.Exception.Message,
                ValidationException _ => context.Exception.Message,
                AuthenticationException _ => "Action is permitted because of authentication reasons",
                _ => "Internal error occured. Please try later"
            };
            var message = context.Exception switch
            {
                ApiException apiException => apiException.Detail,
                ArgumentNullException _ => context.Exception.Message,
                ValidationException _ => context.Exception.Message,
                AuthenticationException _ => "Action is permitted because of authentication reasons",
                _ => "Internal error occured. Please try later"
            };
            var problemDetails = new ProblemDetails
            {
                Title = title,
                Status = statusCode,
                Detail = message,
            };

            if (problemDetails.Status >= StatusCodes.Status500InternalServerError)
                _logger.LogError(context.Exception, "critical error handled");
            else if (problemDetails.Status >= StatusCodes.Status400BadRequest)
                _logger.LogError(context.Exception, "Request error handled");

            var response = BuildResponse(problemDetails);
            context.HttpContext.Response.StatusCode = response.StatusCode ?? StatusCodes.Status500InternalServerError;
            context.Result = response;
            context.ExceptionHandled = true;
        }
        private static ObjectResult BuildResponse(ProblemDetails problem) =>
        new ObjectResult(problem)
        {
            StatusCode = problem.Status ?? StatusCodes.Status500InternalServerError,
            ContentTypes = new MediaTypeCollection
            {
                "application/problem+json"
            }
        };
    }
}
