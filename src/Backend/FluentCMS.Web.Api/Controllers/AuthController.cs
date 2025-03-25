using FluentCMS.Entities.Authentication;
using FluentCMS.Repositories.Abstractions;
using FluentCMS.Web.Api.Authentication.Models;
using FluentCMS.Web.Api.Authentication.Services;
using FluentCMS.Web.Api.Common.Extensions;
using FluentCMS.Web.Api.Common.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace FluentCMS.Web.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IBaseEntityRepository<User> _userRepository;
    private readonly IBaseEntityRepository<RefreshToken> _refreshTokenRepository;
    private readonly IBaseEntityRepository<MfaToken> _mfaTokenRepository;
    private readonly IJwtTokenService _jwtTokenService;

    public AuthController(
        IBaseEntityRepository<User> userRepository,
        IBaseEntityRepository<RefreshToken> refreshTokenRepository,
        IBaseEntityRepository<MfaToken> mfaTokenRepository,
        IJwtTokenService jwtTokenService)
    {
        _userRepository = userRepository;
        _refreshTokenRepository = refreshTokenRepository;
        _mfaTokenRepository = mfaTokenRepository;
        _jwtTokenService = jwtTokenService;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<ApiResponse<UserResponse>>> Register([FromBody] RegisterRequest model)
    {
        // Check if username is already taken
        var existingUsers = await _userRepository.GetAll();
        if (existingUsers.Any(u => u.Username.Equals(model.Username, StringComparison.OrdinalIgnoreCase)))
        {
            return this.ApiBadRequest<UserResponse>("Username is already taken");
        }

        // Check if email is already taken
        if (existingUsers.Any(u => u.Email.Equals(model.Email, StringComparison.OrdinalIgnoreCase)))
        {
            return this.ApiBadRequest<UserResponse>("Email is already registered");
        }

        // Generate salt and hash password
        var salt = SecurityHelper.GenerateSalt();
        var passwordHash = SecurityHelper.HashPassword(model.Password, salt);

        // Create new user
        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = model.Username,
            Email = model.Email,
            PasswordHash = passwordHash,
            PasswordSalt = salt,
            CreatedDate = DateTime.UtcNow,
            EmailConfirmed = false, // Implement email confirmation flow if needed
            IsMfaEnabled = false
        };

        var createdUser = await _userRepository.Create(user);
        if (createdUser == null)
        {
            return this.ApiServerError<UserResponse>("Failed to create user");
        }

        // Return user data
        var userResponse = new UserResponse
        {
            Id = createdUser.Id,
            Username = createdUser.Username,
            Email = createdUser.Email,
            IsMfaEnabled = createdUser.IsMfaEnabled
        };

        return this.ApiOk(userResponse, "User registered successfully");
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<ApiResponse<AuthResponse>>> Login([FromBody] LoginRequest model)
    {
        // Find user by username
        var users = await _userRepository.GetAll();
        var user = users.FirstOrDefault(u => u.Username.Equals(model.Username, StringComparison.OrdinalIgnoreCase));
        
        if (user == null)
        {
            return this.ApiBadRequest<AuthResponse>("Invalid username or password");
        }

        // Check if account is locked
        if (user.IsLocked)
        {
            return this.ApiBadRequest<AuthResponse>("Account is locked. Try again later.");
        }

        // Verify password
        if (!SecurityHelper.VerifyPassword(model.Password, user.PasswordHash, user.PasswordSalt))
        {
            // Increment failed attempts and lock account if necessary
            user.AccessFailedCount++;
            if (user.AccessFailedCount >= 5) // Max failed attempts
            {
                user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15); // Lock for 15 minutes
            }
            
            await _userRepository.Update(user);
            
            return this.ApiBadRequest<AuthResponse>("Invalid username or password");
        }

        // Reset failed attempts if login is successful
        if (user.AccessFailedCount > 0)
        {
            user.AccessFailedCount = 0;
            await _userRepository.Update(user);
        }

        // Check if MFA is required
        if (user.IsMfaEnabled)
        {
            // Generate MFA token for verification
            var mfaToken = _jwtTokenService.GenerateMfaToken(user.Id);
            await _mfaTokenRepository.Create(mfaToken);

            // Generate JWT token with MFA required claim
            var accessToken = _jwtTokenService.GenerateAccessToken(user, requiresMfa: true);
            
            // Get the expiration from JWT settings
            var expiration = DateTime.UtcNow.AddMinutes(15); // Default to 15 minutes

            return this.ApiOk(new AuthResponse
            {
                AccessToken = accessToken,
                RefreshToken = string.Empty, // Don't provide refresh token until MFA is verified
                RequiresMfa = true,
                MfaToken = mfaToken.Token,
                Expiration = expiration
            });
        }

        // MFA not required, generate tokens
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var refreshToken = _jwtTokenService.GenerateRefreshToken(user.Id, ipAddress);
        await _refreshTokenRepository.Create(refreshToken);

        var token = _jwtTokenService.GenerateAccessToken(user);
        
        // Get the expiration from JWT settings
        var tokenExpiration = DateTime.UtcNow.AddMinutes(15); // Default to 15 minutes

        return this.ApiOk(new AuthResponse
        {
            AccessToken = token,
            RefreshToken = refreshToken.Token,
            RequiresMfa = false,
            Expiration = tokenExpiration
        });
    }

    [HttpPost("refresh-token")]
    [AllowAnonymous]
    public async Task<ActionResult<ApiResponse<AuthResponse>>> RefreshToken([FromBody] RefreshTokenRequest model)
    {
        // Find the refresh token
        var refreshTokens = await _refreshTokenRepository.GetAll();
        var storedToken = refreshTokens.FirstOrDefault(t => t.Token == model.RefreshToken);

        if (storedToken == null)
        {
            return this.ApiBadRequest<AuthResponse>("Invalid refresh token");
        }

        if (!storedToken.IsActive)
        {
            return this.ApiBadRequest<AuthResponse>("Inactive refresh token");
        }

        // Get user
        var user = await _userRepository.GetById(storedToken.UserId);
        if (user == null)
        {
            return this.ApiBadRequest<AuthResponse>("Invalid refresh token");
        }

        // Revoke the current refresh token
        storedToken.Revoked = DateTime.UtcNow;
        storedToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        storedToken.ReasonRevoked = "Replaced by new token";
        await _refreshTokenRepository.Update(storedToken);

        // Generate new refresh token
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var newRefreshToken = _jwtTokenService.GenerateRefreshToken(user.Id, ipAddress);
        storedToken.ReplacedByToken = newRefreshToken.Token;
        await _refreshTokenRepository.Create(newRefreshToken);

        // Generate new JWT token
        var token = _jwtTokenService.GenerateAccessToken(user);
        
        // Get the expiration from JWT settings
        var expiration = DateTime.UtcNow.AddMinutes(15); // Default to 15 minutes

        return this.ApiOk(new AuthResponse
        {
            AccessToken = token,
            RefreshToken = newRefreshToken.Token,
            RequiresMfa = false,
            Expiration = expiration
        });
    }

    [HttpPost("verify-mfa")]
    [AllowAnonymous]
    public async Task<ActionResult<ApiResponse<AuthResponse>>> VerifyMfa([FromBody] VerifyMfaRequest model)
    {
        // Find the MFA token
        var mfaTokens = await _mfaTokenRepository.GetAll();
        var storedToken = mfaTokens.FirstOrDefault(t => t.Token == model.MfaToken);

        if (storedToken == null || !storedToken.IsActive)
        {
            return this.ApiBadRequest<AuthResponse>("Invalid or expired MFA token");
        }

        // Get user
        var user = await _userRepository.GetById(storedToken.UserId);
        if (user == null || !user.IsMfaEnabled || string.IsNullOrEmpty(user.MfaSecretKey))
        {
            return this.ApiBadRequest<AuthResponse>("Invalid MFA configuration");
        }

        // Verify MFA code
        if (!SecurityHelper.VerifyMfaCode(user.MfaSecretKey, model.MfaCode))
        {
            return this.ApiBadRequest<AuthResponse>("Invalid MFA code");
        }

        // Mark the token as used
        storedToken.IsUsed = true;
        await _mfaTokenRepository.Update(storedToken);

        // Generate tokens
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var refreshToken = _jwtTokenService.GenerateRefreshToken(user.Id, ipAddress);
        await _refreshTokenRepository.Create(refreshToken);

        var token = _jwtTokenService.GenerateAccessToken(user);
        
        // Get the expiration from JWT settings
        var expiration = DateTime.UtcNow.AddMinutes(15); // Default to 15 minutes

        return this.ApiOk(new AuthResponse
        {
            AccessToken = token,
            RefreshToken = refreshToken.Token,
            RequiresMfa = false,
            Expiration = expiration
        });
    }

    [HttpPost("setup-mfa")]
    [Authorize]
    public async Task<ActionResult<ApiResponse<MfaSetupResponse>>> SetupMfa()
    {
        // Get the current user ID from claims
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            return this.ApiBadRequest<MfaSetupResponse>("Invalid user");
        }

        // Get user
        var user = await _userRepository.GetById(userId);
        if (user == null)
        {
            return this.ApiBadRequest<MfaSetupResponse>("User not found");
        }

        // Generate new MFA secret key
        var secretKey = SecurityHelper.GenerateMfaSecretKey();
        
        // Store the secret key temporarily (not enabled yet until verification)
        user.MfaSecretKey = secretKey;
        await _userRepository.Update(user);

        // In a real app, generate QR code URL for authenticator app
        // For demo, we'll just provide the secret key
        var qrCodeUrl = $"otpauth://totp/FluentCMS:{user.Email}?secret={Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(secretKey))}&issuer=FluentCMS";

        return this.ApiOk(new MfaSetupResponse
        {
            SecretKey = secretKey,
            QrCodeUrl = qrCodeUrl,
            ManualEntryKey = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(secretKey))
        }, "MFA setup initialized successfully");
    }

    [HttpPost("verify-mfa-setup")]
    [Authorize]
    public async Task<ActionResult<ApiResponse<bool>>> VerifyMfaSetup([FromBody] SetupMfaRequest model)
    {
        // Get the current user ID from claims
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            return this.ApiBadRequest<bool>("Invalid user");
        }

        // Get user
        var user = await _userRepository.GetById(userId);
        if (user == null || string.IsNullOrEmpty(user.MfaSecretKey))
        {
            return this.ApiBadRequest<bool>("Invalid MFA configuration");
        }

        // Verify MFA code
        if (!SecurityHelper.VerifyMfaCode(user.MfaSecretKey, model.MfaCode))
        {
            return this.ApiBadRequest<bool>("Invalid MFA code");
        }

        // Enable MFA for user
        user.IsMfaEnabled = true;
        await _userRepository.Update(user);

        return this.ApiOk(true, "MFA has been successfully enabled");
    }

    [HttpPost("disable-mfa")]
    [Authorize]
    public async Task<ActionResult<ApiResponse<bool>>> DisableMfa([FromBody] SetupMfaRequest model)
    {
        // Get the current user ID from claims
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            return this.ApiBadRequest<bool>("Invalid user");
        }

        // Get user
        var user = await _userRepository.GetById(userId);
        if (user == null || string.IsNullOrEmpty(user.MfaSecretKey) || !user.IsMfaEnabled)
        {
            return this.ApiBadRequest<bool>("MFA is not enabled");
        }

        // Verify MFA code one last time before disabling
        if (!SecurityHelper.VerifyMfaCode(user.MfaSecretKey, model.MfaCode))
        {
            return this.ApiBadRequest<bool>("Invalid MFA code");
        }

        // Disable MFA for user
        user.IsMfaEnabled = false;
        user.MfaSecretKey = null;
        await _userRepository.Update(user);

        return this.ApiOk(true, "MFA has been successfully disabled");
    }

    [HttpPost("change-password")]
    [Authorize]
    public async Task<ActionResult<ApiResponse<bool>>> ChangePassword([FromBody] ChangePasswordRequest model)
    {
        // Get the current user ID from claims
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            return this.ApiBadRequest<bool>("Invalid user");
        }

        // Get user
        var user = await _userRepository.GetById(userId);
        if (user == null)
        {
            return this.ApiBadRequest<bool>("User not found");
        }

        // Verify current password
        if (!SecurityHelper.VerifyPassword(model.CurrentPassword, user.PasswordHash, user.PasswordSalt))
        {
            return this.ApiBadRequest<bool>("Current password is incorrect");
        }

        // Update password
        var newSalt = SecurityHelper.GenerateSalt();
        var newPasswordHash = SecurityHelper.HashPassword(model.NewPassword, newSalt);
        
        user.PasswordHash = newPasswordHash;
        user.PasswordSalt = newSalt;
        user.LastModifiedDate = DateTime.UtcNow;
        
        await _userRepository.Update(user);

        // Revoke all refresh tokens for user for security
        var refreshTokens = await _refreshTokenRepository.GetAll();
        var userTokens = refreshTokens.Where(t => t.UserId == userId && t.IsActive).ToList();
        
        foreach (var token in userTokens)
        {
            token.Revoked = DateTime.UtcNow;
            token.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            token.ReasonRevoked = "Password changed";
            await _refreshTokenRepository.Update(token);
        }

        return this.ApiOk(true, "Password has been changed successfully");
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<ActionResult<ApiResponse<bool>>> Logout()
    {
        // Get the current user ID from claims
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            return this.ApiOk(true); // Still return success even if no valid user
        }
        
        // Try to get the refresh token from the request
        var token = Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
        if (!string.IsNullOrEmpty(token))
        {
            var userIdFromToken = _jwtTokenService.GetUserIdFromToken(token);
            if (userIdFromToken.HasValue && userIdFromToken.Value == userId)
            {
                // Find any active refresh tokens for this token
                var refreshTokens = await _refreshTokenRepository.GetAll();
                var userTokens = refreshTokens.Where(t => t.UserId == userId && t.IsActive).ToList();
                
                foreach (var refreshToken in userTokens)
                {
                    refreshToken.Revoked = DateTime.UtcNow;
                    refreshToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    refreshToken.ReasonRevoked = "User logout";
                    await _refreshTokenRepository.Update(refreshToken);
                }
            }
        }

        return this.ApiOk(true, "Logged out successfully");
    }
}
