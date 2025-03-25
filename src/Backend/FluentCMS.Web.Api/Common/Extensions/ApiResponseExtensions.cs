using Microsoft.AspNetCore.Mvc;
using FluentCMS.Web.Api.Common.Models;

namespace FluentCMS.Web.Api.Common.Extensions;

/// <summary>
/// Extension methods for ControllerBase to standardize API responses
/// </summary>
public static class ApiResponseExtensions
{
    /// <summary>
    /// Return a success response with data and 200 status code
    /// </summary>
    public static ActionResult<ApiResponse<T>> ApiOk<T>(this ControllerBase controller, T data, string message = "Operation successful")
    {
        var response = ApiResponse<T>.SuccessResponse(data, message);
        return controller.Ok(response);
    }
    
    /// <summary>
    /// Return a success response without data and 200 status code
    /// </summary>
    public static ActionResult<ApiResponse> ApiOk(this ControllerBase controller, string message = "Operation successful")
    {
        var response = ApiResponse.SuccessResponse(message);
        return controller.Ok(response);
    }
    
    /// <summary>
    /// Return a created response with data and 201 status code
    /// </summary>
    public static ActionResult<ApiResponse<T>> ApiCreated<T>(this ControllerBase controller, T data, string message = "Resource created successfully")
    {
        var response = new ApiResponse<T>
        {
            Success = true,
            Message = message,
            StatusCode = 201,
            Data = data
        };
        return controller.StatusCode(201, response);
    }
    
    /// <summary>
    /// Return a bad request response with 400 status code
    /// </summary>
    public static ActionResult<ApiResponse<T>> ApiBadRequest<T>(this ControllerBase controller, string message, List<string>? errors = null)
    {
        var response = ApiResponse<T>.ErrorResponse(message, 400, errors);
        return controller.BadRequest(response);
    }
    
    /// <summary>
    /// Return a bad request response with 400 status code
    /// </summary>
    public static ActionResult<ApiResponse> ApiBadRequest(this ControllerBase controller, string message, List<string>? errors = null)
    {
        var response = ApiResponse.ErrorResponse(message, 400, errors);
        return controller.BadRequest(response);
    }
    
    /// <summary>
    /// Return a not found response with 404 status code
    /// </summary>
    public static ActionResult<ApiResponse<T>> ApiNotFound<T>(this ControllerBase controller, string message = "Resource not found")
    {
        var response = ApiResponse<T>.ErrorResponse(message, 404);
        return controller.NotFound(response);
    }
    
    /// <summary>
    /// Return a not found response with 404 status code
    /// </summary>
    public static ActionResult<ApiResponse> ApiNotFound(this ControllerBase controller, string message = "Resource not found")
    {
        var response = ApiResponse.ErrorResponse(message, 404);
        return controller.NotFound(response);
    }
    
    /// <summary>
    /// Return an unauthorized response with 401 status code
    /// </summary>
    public static ActionResult<ApiResponse<T>> ApiUnauthorized<T>(this ControllerBase controller, string message = "Unauthorized access")
    {
        var response = ApiResponse<T>.ErrorResponse(message, 401);
        return controller.Unauthorized(response);
    }
    
    /// <summary>
    /// Return an unauthorized response with 401 status code
    /// </summary>
    public static ActionResult<ApiResponse> ApiUnauthorized(this ControllerBase controller, string message = "Unauthorized access")
    {
        var response = ApiResponse.ErrorResponse(message, 401);
        return controller.Unauthorized(response);
    }
    
    /// <summary>
    /// Return a forbidden response with 403 status code
    /// </summary>
    public static ActionResult<ApiResponse<T>> ApiForbidden<T>(this ControllerBase controller, string message = "Forbidden access")
    {
        var response = ApiResponse<T>.ErrorResponse(message, 403);
        return controller.StatusCode(403, response);
    }
    
    /// <summary>
    /// Return a forbidden response with 403 status code
    /// </summary>
    public static ActionResult<ApiResponse> ApiForbidden(this ControllerBase controller, string message = "Forbidden access")
    {
        var response = ApiResponse.ErrorResponse(message, 403);
        return controller.StatusCode(403, response);
    }
    
    /// <summary>
    /// Return a server error response with 500 status code
    /// </summary>
    public static ActionResult<ApiResponse<T>> ApiServerError<T>(this ControllerBase controller, string message = "Internal server error")
    {
        var response = ApiResponse<T>.ErrorResponse(message, 500);
        return controller.StatusCode(500, response);
    }
    
    /// <summary>
    /// Return a server error response with 500 status code
    /// </summary>
    public static ActionResult<ApiResponse> ApiServerError(this ControllerBase controller, string message = "Internal server error")
    {
        var response = ApiResponse.ErrorResponse(message, 500);
        return controller.StatusCode(500, response);
    }
    
    /// <summary>
    /// Return a validation error response with errors from ModelState
    /// </summary>
    public static ActionResult<ApiResponse<T>> ApiValidationError<T>(this ControllerBase controller)
    {
        var errors = controller.ModelState
            .Where(e => e.Value?.Errors.Count > 0)
            .SelectMany(e => e.Value!.Errors)
            .Select(e => e.ErrorMessage)
            .ToList();
        
        var response = ApiResponse<T>.ErrorResponse("Validation failed", 400, errors);
        return controller.BadRequest(response);
    }
    
    /// <summary>
    /// Return a validation error response with errors from ModelState
    /// </summary>
    public static ActionResult<ApiResponse> ApiValidationError(this ControllerBase controller)
    {
        var errors = controller.ModelState
            .Where(e => e.Value?.Errors.Count > 0)
            .SelectMany(e => e.Value!.Errors)
            .Select(e => e.ErrorMessage)
            .ToList();
        
        var response = ApiResponse.ErrorResponse("Validation failed", 400, errors);
        return controller.BadRequest(response);
    }
}
