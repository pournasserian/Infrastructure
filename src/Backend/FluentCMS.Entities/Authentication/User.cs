using System.ComponentModel.DataAnnotations;

namespace FluentCMS.Entities.Authentication;

public class User : AuditableEntity
{
    [Required]
    [MaxLength(100)]
    public string Username { get; set; } = string.Empty;
    
    [Required]
    [EmailAddress]
    [MaxLength(100)]
    public string Email { get; set; } = string.Empty;
    
    // Store password hash, not plain password
    [Required]
    public string PasswordHash { get; set; } = string.Empty;
    
    // Salt for password hashing
    [Required]
    public string PasswordSalt { get; set; } = string.Empty;
    
    // For account lockout
    public DateTimeOffset? LockoutEnd { get; set; }
    public bool IsLocked => LockoutEnd != null && LockoutEnd > DateTimeOffset.UtcNow;
    public int AccessFailedCount { get; set; }
    
    // For email verification and account confirmation
    public bool EmailConfirmed { get; set; }
    
    // For MFA
    public bool IsMfaEnabled { get; set; }
    public string? MfaSecretKey { get; set; }
}
