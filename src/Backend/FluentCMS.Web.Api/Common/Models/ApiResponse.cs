namespace FluentCMS.Web.Api.Common.Models;

/// <summary>
/// Base non-generic API response
/// </summary>
public class ApiResponse
{
    /// <summary>
    /// Indicates if the request was successful
    /// </summary>
    public bool Success { get; set; }
    
    /// <summary>
    /// Response message
    /// </summary>
    public string? Message { get; set; }
    
    /// <summary>
    /// HTTP status code
    /// </summary>
    public int StatusCode { get; set; }
    
    /// <summary>
    /// Error details if any
    /// </summary>
    public List<string>? Errors { get; set; }
    
    /// <summary>
    /// Timestamp of the response
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Create a success response
    /// </summary>
    public static ApiResponse SuccessResponse(string message = "Operation successful")
    {
        var response = new ApiResponse
        {
            Success = true,
            Message = message,
            StatusCode = 200
        };
        return response;
    }
    
    /// <summary>
    /// Create an error response
    /// </summary>
    public static ApiResponse ErrorResponse(string message, int statusCode = 400, List<string>? errors = null)
    {
        var response = new ApiResponse
        {
            Success = false,
            Message = message,
            StatusCode = statusCode,
            Errors = errors
        };
        return response;
    }
}

/// <summary>
/// Generic API response with data
/// </summary>
public class ApiResponse<T> : ApiResponse
{
    /// <summary>
    /// Response data
    /// </summary>
    public T? Data { get; set; }
    
    /// <summary>
    /// Create a success response with data
    /// </summary>
    public static new ApiResponse<T> SuccessResponse(T data, string message = "Operation successful")
    {
        var response = new ApiResponse<T>
        {
            Success = true,
            Message = message,
            StatusCode = 200,
            Data = data
        };
        return response;
    }
    
    /// <summary>
    /// Create an error response
    /// </summary>
    public static new ApiResponse<T> ErrorResponse(string message, int statusCode = 400, List<string>? errors = null)
    {
        var response = new ApiResponse<T>
        {
            Success = false,
            Message = message,
            StatusCode = statusCode,
            Errors = errors,
            Data = default
        };
        return response;
    }
}
