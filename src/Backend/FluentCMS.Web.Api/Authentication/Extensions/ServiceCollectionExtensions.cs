using FluentCMS.Entities.Authentication;
using FluentCMS.Repositories.Abstractions;
using FluentCMS.Web.Api.Authentication.Configuration;
using FluentCMS.Web.Api.Authentication.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace FluentCMS.Web.Api.Authentication.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        // Configure JWT settings
        var jwtSettingsSection = configuration.GetSection(JwtSettings.SectionName);
        services.Configure<JwtSettings>(jwtSettingsSection);
        
        // Get JWT settings for token validation
        var jwtSettings = jwtSettingsSection.Get<JwtSettings>();
        var key = Encoding.ASCII.GetBytes(jwtSettings?.Secret ?? throw new InvalidOperationException("JWT Secret key is not configured."));
        
        // Add JWT authentication
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.RequireHttpsMetadata = false; // Set to true in production
            options.SaveToken = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = jwtSettings.Issuer,
                ValidateAudience = true,
                ValidAudience = jwtSettings.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
        });
        
        // Add authorization
        services.AddAuthorization(options =>
        {
            // Require authenticated users by default
            options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
                
            // Policy for requiring MFA to be completed
            options.AddPolicy("RequireMfa", policy =>
                policy.RequireClaim("mfa_required", "false"));
        });
        
        // Register token service
        services.AddScoped<IJwtTokenService, JwtTokenService>();
        
        return services;
    }
    
    public static IServiceCollection AddAuthenticationRepositories(this IServiceCollection services)
    {
        // Register repositories for auth entities
        services.AddScoped<IBaseEntityRepository<User>>();
        services.AddScoped<IBaseEntityRepository<RefreshToken>>();
        services.AddScoped<IBaseEntityRepository<MfaToken>>();
        
        return services;
    }
}
