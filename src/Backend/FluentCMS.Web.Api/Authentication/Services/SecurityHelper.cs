using System.Security.Cryptography;
using System.Text;

namespace FluentCMS.Web.Api.Authentication.Services;

public static class SecurityHelper
{
    // Generate a random salt
    public static string GenerateSalt()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes);
    }
    
    // Hash a password with a given salt using PBKDF2
    public static string HashPassword(string password, string salt)
    {
        // Convert the strings to byte arrays
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] saltBytes = Convert.FromBase64String(salt);
        
        // Create the hash with PBKDF2 (Password-Based Key Derivation Function 2)
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            passwordBytes,
            saltBytes,
            100000, // Number of iterations (OWASP recommendation)
            HashAlgorithmName.SHA512,
            64); // 64 bytes = 512 bits
        
        return Convert.ToBase64String(hash);
    }
    
    // Verify a password against a stored hash and salt
    public static bool VerifyPassword(string password, string storedHash, string storedSalt)
    {
        string computedHash = HashPassword(password, storedSalt);
        return computedHash == storedHash;
    }
    
    // Generate a random token
    public static string GenerateRandomToken()
    {
        var randomBytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(randomBytes);
    }
    
    // Generate a time-based MFA code (for demonstration, in real app use a library like OtpNet)
    public static string GenerateMfaCode(string secretKey)
    {
        // Simple implementation for demonstration
        // In a real app, use a proper TOTP implementation
        
        // Get current time slice (30 second intervals)
        var timeSlice = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var timeBytes = BitConverter.GetBytes(timeSlice);
        
        // Convert secret key to bytes
        var keyBytes = Convert.FromBase64String(secretKey);
        
        // Create HMAC
        using var hmac = new HMACSHA1(keyBytes);
        var hash = hmac.ComputeHash(timeBytes);
        
        // Get offset and generate 6-digit code
        var offset = hash[^1] & 0x0F;
        var code = ((hash[offset] & 0x7F) << 24) |
                  ((hash[offset + 1] & 0xFF) << 16) |
                  ((hash[offset + 2] & 0xFF) << 8) |
                  (hash[offset + 3] & 0xFF);
        
        return (code % 1000000).ToString("D6");
    }
    
    // Verify MFA code
    public static bool VerifyMfaCode(string secretKey, string inputCode)
    {
        var generatedCode = GenerateMfaCode(secretKey);
        return generatedCode == inputCode;
    }
    
    // Generate a new MFA secret key
    public static string GenerateMfaSecretKey()
    {
        var bytes = RandomNumberGenerator.GetBytes(20); // Standard size for TOTP
        return Convert.ToBase64String(bytes);
    }
}
