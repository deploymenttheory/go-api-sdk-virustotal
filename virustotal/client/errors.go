package client

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// HTTP Status Codes from VirusTotal API v3 Documentation
const (
	// Success status codes
	StatusOK      = 200 // Successful GET requests
	StatusCreated = 201 // Successful POST requests

	// Client error status codes
	StatusBadRequest          = 400 // Bad request, invalid arguments, query errors
	StatusUnauthorized        = 401 // Authentication required, invalid API key, inactive user
	StatusForbidden           = 403 // Forbidden operation
	StatusNotFound            = 404 // Resource not found
	StatusConflict            = 409 // Resource already exists
	StatusFailedDependency    = 424 // Request depended on another request that failed
	StatusTooManyRequests     = 429 // Quota exceeded or too many requests
	StatusUnprocessableEntity = 422 // Validation errors

	// Server error status codes
	StatusInternalServerError = 500 // Server-side error
	StatusBadGateway          = 502 // Gateway error
	StatusServiceUnavailable  = 503 // Transient error, service temporarily unavailable
	StatusGatewayTimeout      = 504 // Deadline exceeded
)

// VirusTotal API Error Codes
const (
	ErrorCodeBadRequest              = "BadRequestError"
	ErrorCodeInvalidArgument         = "InvalidArgumentError"
	ErrorCodeNotAvailableYet         = "NotAvailableYet"
	ErrorCodeUnselectiveContentQuery = "UnselectiveContentQueryError"
	ErrorCodeUnsupportedContentQuery = "UnsupportedContentQueryError"
	ErrorCodeAuthenticationRequired  = "AuthenticationRequiredError"
	ErrorCodeUserNotActive           = "UserNotActiveError"
	ErrorCodeWrongCredentials        = "WrongCredentialsError"
	ErrorCodeForbidden               = "ForbiddenError"
	ErrorCodeNotFound                = "NotFoundError"
	ErrorCodeAlreadyExists           = "AlreadyExistsError"
	ErrorCodeFailedDependency        = "FailedDependencyError"
	ErrorCodeQuotaExceeded           = "QuotaExceededError"
	ErrorCodeTooManyRequests         = "TooManyRequestsError"
	ErrorCodeTransient               = "TransientError"
	ErrorCodeDeadlineExceeded        = "DeadlineExceededError"
)

// APIError represents an error response from the VirusTotal API
// Matches the error schema from API v3 documentation:
//
//	{
//	  "error": {
//	    "code": "<error code>",
//	    "message": "<a message describing the error>"
//	  }
//	}
type APIError struct {
	Code    string `json:"code"`    // Error code (e.g., "NotFoundError")
	Message string `json:"message"` // Error message

	// HTTP response details
	StatusCode int    // HTTP status code
	Status     string // HTTP status text
	Endpoint   string // API endpoint that returned the error
	Method     string // HTTP method used
}

// vtErrorResponse represents the VirusTotal API error response wrapper
type vtErrorResponse struct {
	Error APIError `json:"error"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("VirusTotal API error (%d %s) [%s] at %s %s: %s",
			e.StatusCode, e.Status, e.Code, e.Method, e.Endpoint, e.Message)
	}
	return fmt.Sprintf("VirusTotal API error (%d %s) at %s %s: %s",
		e.StatusCode, e.Status, e.Method, e.Endpoint, e.Message)
}

// ParseErrorResponse parses an error response from the API
func ParseErrorResponse(body []byte, statusCode int, status, method, endpoint string, logger *zap.Logger) error {
	apiError := &APIError{
		StatusCode: statusCode,
		Status:     status,
		Endpoint:   endpoint,
		Method:     method,
	}

	// Try to parse as VirusTotal API v3 error response format
	var vtErr vtErrorResponse
	if err := json.Unmarshal(body, &vtErr); err == nil && vtErr.Error.Code != "" {
		// Successfully parsed VT error response
		apiError.Code = vtErr.Error.Code
		apiError.Message = vtErr.Error.Message

		logger.Error("API error response",
			zap.Int("status_code", statusCode),
			zap.String("status", status),
			zap.String("method", method),
			zap.String("endpoint", endpoint),
			zap.String("error_code", apiError.Code),
			zap.String("message", apiError.Message))
	} else {
		// If JSON parsing fails or doesn't match expected format, use raw body as message
		apiError.Message = string(body)
		logger.Debug("Failed to parse error response as VirusTotal error format, using raw body",
			zap.Error(err),
			zap.String("body", string(body)))

		// If no message was parsed, set a default message based on status code
		if apiError.Message == "" {
			apiError.Message = getDefaultErrorMessage(statusCode)
		}

		logger.Error("API error response",
			zap.Int("status_code", statusCode),
			zap.String("status", status),
			zap.String("method", method),
			zap.String("endpoint", endpoint),
			zap.String("message", apiError.Message))
	}

	return apiError
}

// getDefaultErrorMessage returns a default error message based on status code
// Messages are mapped to official VirusTotal API documentation: https://docs.virustotal.com/reference/errors
func getDefaultErrorMessage(statusCode int) string {
	switch statusCode {
	case StatusBadRequest:
		return "The API request is invalid or malformed. The message usually provides details about why the request is not valid."
	case StatusUnauthorized:
		return "The operation requires an authenticated user. Verify that you have provided your correct API key."
	case StatusForbidden:
		return "You are not allowed to perform the requested operation."
	case StatusNotFound:
		return "The requested resource was not found."
	case StatusConflict:
		return "The resource already exists."
	case StatusUnprocessableEntity:
		return "Validation error"
	case StatusFailedDependency:
		return "The request depended on another request and that request failed."
	case StatusTooManyRequests:
		return "You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC. You may have run out of disk space and/or number of files on your VirusTotal Monitor account. Or too many requests have been made in a given amount of time."
	case StatusInternalServerError:
		return "Internal server error"
	case StatusBadGateway:
		return "Bad gateway"
	case StatusServiceUnavailable:
		return "Transient server error. Retry might work."
	case StatusGatewayTimeout:
		return "The operation took too long to complete."
	default:
		return "Unknown error"
	}
}

// Error type check helpers

// IsBadRequest checks if the error is a bad request error (400)
func IsBadRequest(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusBadRequest
	}
	return false
}

// IsUnauthorized checks if the error is an authentication error (401)
func IsUnauthorized(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusUnauthorized
	}
	return false
}

// IsForbidden checks if the error is a forbidden error (403)
func IsForbidden(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusForbidden
	}
	return false
}

// IsNotFound checks if the error is a not found error (404)
func IsNotFound(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusNotFound
	}
	return false
}

// IsConflict checks if the error is a conflict error (409) - resource already exists
func IsConflict(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusConflict
	}
	return false
}

// IsValidationError checks if the error is a validation/unprocessable entity error (422)
func IsValidationError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusUnprocessableEntity
	}
	return false
}

// IsQuotaExceeded checks if the error is a quota exceeded error (429)
func IsQuotaExceeded(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusTooManyRequests &&
			(apiErr.Code == ErrorCodeQuotaExceeded || apiErr.Code == ErrorCodeTooManyRequests)
	}
	return false
}

// IsRateLimited checks if the error is a rate limit error (429)
func IsRateLimited(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusTooManyRequests
	}
	return false
}

// IsServerError checks if the error is a server error (5xx)
func IsServerError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode >= 500 && apiErr.StatusCode < 600
	}
	return false
}

// IsTransient checks if the error is transient and can be retried
func IsTransient(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Code == ErrorCodeTransient ||
			apiErr.StatusCode == StatusServiceUnavailable ||
			apiErr.StatusCode == StatusGatewayTimeout
	}
	return false
}

// IsAuthenticationError checks if the error is any authentication-related error
func IsAuthenticationError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		if apiErr.StatusCode == StatusUnauthorized {
			return true
		}

		return apiErr.Code == ErrorCodeAuthenticationRequired ||
			apiErr.Code == ErrorCodeUserNotActive ||
			apiErr.Code == ErrorCodeWrongCredentials
	}
	return false
}

// IsInvalidArgument checks if the error is due to invalid arguments
func IsInvalidArgument(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Code == ErrorCodeInvalidArgument
	}
	return false
}

// IsNotAvailableYet checks if the resource is not available yet but will be later
func IsNotAvailableYet(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Code == ErrorCodeNotAvailableYet
	}
	return false
}

// IsUserNotActive checks if the error is due to inactive user account
func IsUserNotActive(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Code == ErrorCodeUserNotActive
	}
	return false
}

// IsWrongCredentials checks if the error is due to incorrect API key
func IsWrongCredentials(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Code == ErrorCodeWrongCredentials
	}
	return false
}

// IsAlreadyExists checks if the error is due to resource already existing
func IsAlreadyExists(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusConflict || apiErr.Code == ErrorCodeAlreadyExists
	}
	return false
}

// IsFailedDependency checks if the error is due to a dependent request failing
func IsFailedDependency(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusFailedDependency || apiErr.Code == ErrorCodeFailedDependency
	}
	return false
}

// IsDeadlineExceeded checks if the operation took too long to complete
func IsDeadlineExceeded(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == StatusGatewayTimeout || apiErr.Code == ErrorCodeDeadlineExceeded
	}
	return false
}

// IsQueryError checks if the error is related to query issues
func IsQueryError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Code == ErrorCodeUnselectiveContentQuery ||
			apiErr.Code == ErrorCodeUnsupportedContentQuery
	}
	return false
}

// GetErrorCode returns the VirusTotal error code from the error
func GetErrorCode(err error) string {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Code
	}
	return ""
}

// IsMonitorQuotaError checks if the error is specifically about Monitor quota/disk space
func IsMonitorQuotaError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		if apiErr.StatusCode == StatusTooManyRequests {

			msg := strings.ToLower(apiErr.Message)
			return strings.Contains(msg, "disk space") ||
				strings.Contains(msg, "virustotal monitor")
		}
	}
	return false
}
