using FluentCMS.Web.Api.Authentication.Extensions;
using FluentCMS.Web.Api.Common.Middleware;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers()
    .ConfigureApiBehaviorOptions(options =>
    {
        // Configure automatic validation response
        options.InvalidModelStateResponseFactory = context =>
        {
            var errors = context.ModelState
                .Where(e => e.Value?.Errors.Count > 0)
                .SelectMany(e => e.Value!.Errors)
                .Select(e => e.ErrorMessage)
                .ToList();

            var response = FluentCMS.Web.Api.Common.Models.ApiResponse.ErrorResponse(
                "Validation failed", 400, errors);
                
            return new BadRequestObjectResult(response);
        };
    });

builder.Services.AddOpenApi();

// Add JWT authentication services
builder.Services.AddJwtAuthentication(builder.Configuration);

// Add auth repositories
builder.Services.AddAuthenticationRepositories();

var app = builder.Build();

// Add global exception handler
app.UseGlobalExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Add authentication middleware before authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
