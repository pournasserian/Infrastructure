using FluentCMS.Entities.Authentication;
using System.Security.Claims;

namespace FluentCMS.Web.Api.Authentication.Services;

public interface IJwtTokenService
{
    // Generate JWT access token
    string GenerateAccessToken(User user, bool requiresMfa = false);
    
    // Validate an access token and return the principal
    ClaimsPrincipal? ValidateToken(string token);
    
    // Generate a refresh token
    RefreshToken GenerateRefreshToken(Guid userId, string ipAddress);
    
    // Generate a MFA token
    MfaToken GenerateMfaToken(Guid userId);
    
    // Get user ID from token
    Guid? GetUserIdFromToken(string token);
    
    // Get claims from token
    IEnumerable<Claim> GetClaimsFromToken(string token);
}
