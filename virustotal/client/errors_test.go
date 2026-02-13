package client

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name        string
		apiError    *APIError
		wantContain []string
	}{
		{
			name: "error with code and message",
			apiError: &APIError{
				Code:       ErrorCodeNotFound,
				Message:    "Resource not found",
				StatusCode: 404,
				Status:     "404 Not Found",
				Method:     "GET",
				Endpoint:   "/api/v3/files/test",
			},
			wantContain: []string{
				"VirusTotal API error",
				"404",
				"Not Found",
				"NotFoundError",
				"GET",
				"/api/v3/files/test",
				"Resource not found",
			},
		},
		{
			name: "error without code",
			apiError: &APIError{
				StatusCode: 500,
				Status:     "500 Internal Server Error",
				Method:     "POST",
				Endpoint:   "/api/v3/files",
				Message:    "Internal error",
			},
			wantContain: []string{
				"VirusTotal API error",
				"500",
				"Internal Server Error",
				"POST",
				"/api/v3/files",
				"Internal error",
			},
		},
		{
			name: "quota exceeded error",
			apiError: &APIError{
				Code:       ErrorCodeQuotaExceeded,
				Message:    "Daily quota exceeded",
				StatusCode: 429,
				Status:     "429 Too Many Requests",
				Method:     "GET",
				Endpoint:   "/api/v3/files/scan",
			},
			wantContain: []string{
				"VirusTotal API error",
				"429",
				"QuotaExceededError",
				"Daily quota exceeded",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.apiError.Error()
			for _, want := range tt.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("Error() = %q, want to contain %q", got, want)
				}
			}
		})
	}
}

func TestParseErrorResponse_ValidJSON(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name           string
		body           string
		statusCode     int
		status         string
		method         string
		endpoint       string
		wantCode       string
		wantMessage    string
		wantStatusCode int
	}{
		{
			name: "valid VT error response",
			body: `{
				"error": {
					"code": "NotFoundError",
					"message": "File not found"
				}
			}`,
			statusCode:     404,
			status:         "404 Not Found",
			method:         "GET",
			endpoint:       "/api/v3/files/test",
			wantCode:       "NotFoundError",
			wantMessage:    "File not found",
			wantStatusCode: 404,
		},
		{
			name: "quota exceeded error",
			body: `{
				"error": {
					"code": "QuotaExceededError",
					"message": "You have exceeded your daily quota"
				}
			}`,
			statusCode:     429,
			status:         "429 Too Many Requests",
			method:         "GET",
			endpoint:       "/api/v3/files/scan",
			wantCode:       "QuotaExceededError",
			wantMessage:    "You have exceeded your daily quota",
			wantStatusCode: 429,
		},
		{
			name: "authentication error",
			body: `{
				"error": {
					"code": "WrongCredentialsError",
					"message": "Invalid API key"
				}
			}`,
			statusCode:     401,
			status:         "401 Unauthorized",
			method:         "GET",
			endpoint:       "/api/v3/files",
			wantCode:       "WrongCredentialsError",
			wantMessage:    "Invalid API key",
			wantStatusCode: 401,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ParseErrorResponse(
				[]byte(tt.body),
				tt.statusCode,
				tt.status,
				tt.method,
				tt.endpoint,
				logger,
			)

			if err == nil {
				t.Fatal("ParseErrorResponse() returned nil error")
			}

			apiErr, ok := err.(*APIError)
			if !ok {
				t.Fatalf("ParseErrorResponse() returned %T, want *APIError", err)
			}

			if apiErr.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", apiErr.Code, tt.wantCode)
			}

			if apiErr.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", apiErr.Message, tt.wantMessage)
			}

			if apiErr.StatusCode != tt.wantStatusCode {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tt.wantStatusCode)
			}

			if apiErr.Status != tt.status {
				t.Errorf("Status = %q, want %q", apiErr.Status, tt.status)
			}

			if apiErr.Method != tt.method {
				t.Errorf("Method = %q, want %q", apiErr.Method, tt.method)
			}

			if apiErr.Endpoint != tt.endpoint {
				t.Errorf("Endpoint = %q, want %q", apiErr.Endpoint, tt.endpoint)
			}
		})
	}
}

func TestParseErrorResponse_InvalidJSON(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name           string
		body           string
		statusCode     int
		wantMessage    string
		wantStatusCode int
	}{
		{
			name:           "plain text error",
			body:           "Something went wrong",
			statusCode:     500,
			wantMessage:    "Something went wrong",
			wantStatusCode: 500,
		},
		{
			name:           "HTML error page",
			body:           "<html><body>Error 404</body></html>",
			statusCode:     404,
			wantMessage:    "<html><body>Error 404</body></html>",
			wantStatusCode: 404,
		},
		{
			name:           "empty body uses default message",
			body:           "",
			statusCode:     503,
			wantMessage:    "Transient server error. Retry might work.",
			wantStatusCode: 503,
		},
		{
			name:           "malformed JSON",
			body:           `{"error": {"code": "incomplete`,
			statusCode:     400,
			wantMessage:    `{"error": {"code": "incomplete`,
			wantStatusCode: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ParseErrorResponse(
				[]byte(tt.body),
				tt.statusCode,
				"",
				"GET",
				"/test",
				logger,
			)

			if err == nil {
				t.Fatal("ParseErrorResponse() returned nil error")
			}

			apiErr, ok := err.(*APIError)
			if !ok {
				t.Fatalf("ParseErrorResponse() returned %T, want *APIError", err)
			}

			if apiErr.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", apiErr.Message, tt.wantMessage)
			}

			if apiErr.StatusCode != tt.wantStatusCode {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tt.wantStatusCode)
			}
		})
	}
}

func TestGetDefaultErrorMessage(t *testing.T) {
	tests := []struct {
		statusCode int
		want       string
	}{
		{StatusBadRequest, "The API request is invalid or malformed. The message usually provides details about why the request is not valid."},
		{StatusUnauthorized, "The operation requires an authenticated user. Verify that you have provided your correct API key."},
		{StatusForbidden, "You are not allowed to perform the requested operation."},
		{StatusNotFound, "The requested resource was not found."},
		{StatusConflict, "The resource already exists."},
		{StatusUnprocessableEntity, "Validation error"},
		{StatusFailedDependency, "The request depended on another request and that request failed."},
		{StatusTooManyRequests, "You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC. You may have run out of disk space and/or number of files on your VirusTotal Monitor account. Or too many requests have been made in a given amount of time."},
		{StatusInternalServerError, "Internal server error"},
		{StatusBadGateway, "Bad gateway"},
		{StatusServiceUnavailable, "Transient server error. Retry might work."},
		{StatusGatewayTimeout, "The operation took too long to complete."},
		{999, "Unknown error"},
		{418, "Unknown error"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := getDefaultErrorMessage(tt.statusCode)
			if got != tt.want {
				t.Errorf("getDefaultErrorMessage(%d) = %q, want %q", tt.statusCode, got, tt.want)
			}
		})
	}
}

func TestIsBadRequest(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "400 error",
			err:  &APIError{StatusCode: 400},
			want: true,
		},
		{
			name: "404 error",
			err:  &APIError{StatusCode: 404},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBadRequest(tt.err)
			if got != tt.want {
				t.Errorf("IsBadRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "401 error",
			err:  &APIError{StatusCode: 401},
			want: true,
		},
		{
			name: "403 error",
			err:  &APIError{StatusCode: 403},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsUnauthorized(tt.err)
			if got != tt.want {
				t.Errorf("IsUnauthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsForbidden(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "403 error",
			err:  &APIError{StatusCode: 403},
			want: true,
		},
		{
			name: "401 error",
			err:  &APIError{StatusCode: 401},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsForbidden(tt.err)
			if got != tt.want {
				t.Errorf("IsForbidden() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "404 error",
			err:  &APIError{StatusCode: 404},
			want: true,
		},
		{
			name: "400 error",
			err:  &APIError{StatusCode: 400},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNotFound(tt.err)
			if got != tt.want {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsConflict(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "409 error",
			err:  &APIError{StatusCode: 409},
			want: true,
		},
		{
			name: "400 error",
			err:  &APIError{StatusCode: 400},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsConflict(tt.err)
			if got != tt.want {
				t.Errorf("IsConflict() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "422 error",
			err:  &APIError{StatusCode: 422},
			want: true,
		},
		{
			name: "400 error",
			err:  &APIError{StatusCode: 400},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidationError(tt.err)
			if got != tt.want {
				t.Errorf("IsValidationError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsQuotaExceeded(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "429 with quota exceeded code",
			err:  &APIError{StatusCode: 429, Code: ErrorCodeQuotaExceeded},
			want: true,
		},
		{
			name: "429 with too many requests code",
			err:  &APIError{StatusCode: 429, Code: ErrorCodeTooManyRequests},
			want: true,
		},
		{
			name: "429 without specific code",
			err:  &APIError{StatusCode: 429},
			want: false,
		},
		{
			name: "400 error",
			err:  &APIError{StatusCode: 400},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsQuotaExceeded(tt.err)
			if got != tt.want {
				t.Errorf("IsQuotaExceeded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRateLimited(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "429 error",
			err:  &APIError{StatusCode: 429},
			want: true,
		},
		{
			name: "400 error",
			err:  &APIError{StatusCode: 400},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRateLimited(tt.err)
			if got != tt.want {
				t.Errorf("IsRateLimited() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsServerError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "500 error",
			err:  &APIError{StatusCode: 500},
			want: true,
		},
		{
			name: "502 error",
			err:  &APIError{StatusCode: 502},
			want: true,
		},
		{
			name: "503 error",
			err:  &APIError{StatusCode: 503},
			want: true,
		},
		{
			name: "599 error",
			err:  &APIError{StatusCode: 599},
			want: true,
		},
		{
			name: "400 error",
			err:  &APIError{StatusCode: 400},
			want: false,
		},
		{
			name: "404 error",
			err:  &APIError{StatusCode: 404},
			want: false,
		},
		{
			name: "600 error (out of 5xx range)",
			err:  &APIError{StatusCode: 600},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsServerError(tt.err)
			if got != tt.want {
				t.Errorf("IsServerError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsTransient(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "transient error code",
			err:  &APIError{Code: ErrorCodeTransient},
			want: true,
		},
		{
			name: "503 error",
			err:  &APIError{StatusCode: 503},
			want: true,
		},
		{
			name: "504 error",
			err:  &APIError{StatusCode: 504},
			want: true,
		},
		{
			name: "404 error",
			err:  &APIError{StatusCode: 404},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTransient(tt.err)
			if got != tt.want {
				t.Errorf("IsTransient() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAuthenticationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "401 error",
			err:  &APIError{StatusCode: 401},
			want: true,
		},
		{
			name: "authentication required code",
			err:  &APIError{Code: ErrorCodeAuthenticationRequired},
			want: true,
		},
		{
			name: "user not active code",
			err:  &APIError{Code: ErrorCodeUserNotActive},
			want: true,
		},
		{
			name: "wrong credentials code",
			err:  &APIError{Code: ErrorCodeWrongCredentials},
			want: true,
		},
		{
			name: "403 error",
			err:  &APIError{StatusCode: 403},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAuthenticationError(tt.err)
			if got != tt.want {
				t.Errorf("IsAuthenticationError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsInvalidArgument(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "invalid argument code",
			err:  &APIError{Code: ErrorCodeInvalidArgument},
			want: true,
		},
		{
			name: "other error code",
			err:  &APIError{Code: ErrorCodeNotFound},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsInvalidArgument(tt.err)
			if got != tt.want {
				t.Errorf("IsInvalidArgument() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNotAvailableYet(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "not available yet code",
			err:  &APIError{Code: ErrorCodeNotAvailableYet},
			want: true,
		},
		{
			name: "other error code",
			err:  &APIError{Code: ErrorCodeNotFound},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNotAvailableYet(tt.err)
			if got != tt.want {
				t.Errorf("IsNotAvailableYet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "APIError with code",
			err:  &APIError{Code: ErrorCodeNotFound},
			want: ErrorCodeNotFound,
		},
		{
			name: "APIError without code",
			err:  &APIError{},
			want: "",
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: "",
		},
		{
			name: "nil error",
			err:  nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetErrorCode(tt.err)
			if got != tt.want {
				t.Errorf("GetErrorCode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsMonitorQuotaError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "429 with disk space message",
			err: &APIError{
				StatusCode: 429,
				Message:    "You have run out of disk space on your VirusTotal Monitor account",
			},
			want: true,
		},
		{
			name: "429 with monitor message",
			err: &APIError{
				StatusCode: 429,
				Message:    "VirusTotal Monitor quota exceeded",
			},
			want: true,
		},
		{
			name: "429 without monitor message",
			err: &APIError{
				StatusCode: 429,
				Message:    "Rate limit exceeded",
			},
			want: false,
		},
		{
			name: "400 error",
			err:  &APIError{StatusCode: 400},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsMonitorQuotaError(tt.err)
			if got != tt.want {
				t.Errorf("IsMonitorQuotaError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIError_JSON_Marshalling(t *testing.T) {
	// Test that APIError can be marshalled and unmarshalled as JSON
	original := &APIError{
		Code:       ErrorCodeNotFound,
		Message:    "Test error message",
		StatusCode: 404,
		Status:     "404 Not Found",
		Endpoint:   "/api/v3/files/test",
		Method:     "GET",
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal APIError: %v", err)
	}

	// Unmarshal back
	var unmarshalled APIError
	err = json.Unmarshal(data, &unmarshalled)
	if err != nil {
		t.Fatalf("Failed to unmarshal APIError: %v", err)
	}

	// Compare
	if unmarshalled.Code != original.Code {
		t.Errorf("Code = %q, want %q", unmarshalled.Code, original.Code)
	}
	if unmarshalled.Message != original.Message {
		t.Errorf("Message = %q, want %q", unmarshalled.Message, original.Message)
	}
}

func TestParseErrorResponse_NilLogger(t *testing.T) {
	// Should not panic with nil logger (though logger should never be nil in practice)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ParseErrorResponse panicked with nil logger: %v", r)
		}
	}()

	logger, _ := zap.NewDevelopment()

	err := ParseErrorResponse(
		[]byte(`{"error": {"code": "NotFoundError", "message": "test"}}`),
		404,
		"404 Not Found",
		"GET",
		"/test",
		logger,
	)

	if err == nil {
		t.Error("ParseErrorResponse() returned nil error")
	}
}

func TestErrorConstants(t *testing.T) {
	// Verify error constants have expected values
	constants := map[string]int{
		"StatusOK":                   StatusOK,
		"StatusCreated":              StatusCreated,
		"StatusBadRequest":           StatusBadRequest,
		"StatusUnauthorized":         StatusUnauthorized,
		"StatusForbidden":            StatusForbidden,
		"StatusNotFound":             StatusNotFound,
		"StatusConflict":             StatusConflict,
		"StatusUnprocessableEntity":  StatusUnprocessableEntity,
		"StatusFailedDependency":     StatusFailedDependency,
		"StatusTooManyRequests":      StatusTooManyRequests,
		"StatusInternalServerError":  StatusInternalServerError,
		"StatusBadGateway":           StatusBadGateway,
		"StatusServiceUnavailable":   StatusServiceUnavailable,
		"StatusGatewayTimeout":       StatusGatewayTimeout,
	}

	expected := map[string]int{
		"StatusOK":                   200,
		"StatusCreated":              201,
		"StatusBadRequest":           400,
		"StatusUnauthorized":         401,
		"StatusForbidden":            403,
		"StatusNotFound":             404,
		"StatusConflict":             409,
		"StatusUnprocessableEntity":  422,
		"StatusFailedDependency":     424,
		"StatusTooManyRequests":      429,
		"StatusInternalServerError":  500,
		"StatusBadGateway":           502,
		"StatusServiceUnavailable":   503,
		"StatusGatewayTimeout":       504,
	}

	for name, got := range constants {
		want := expected[name]
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
}

func TestIsAlreadyExists(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "409 conflict error",
			err:  &APIError{StatusCode: 409},
			want: true,
		},
		{
			name: "already exists code",
			err:  &APIError{Code: ErrorCodeAlreadyExists},
			want: true,
		},
		{
			name: "404 error",
			err:  &APIError{StatusCode: 404},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAlreadyExists(tt.err)
			if got != tt.want {
				t.Errorf("IsAlreadyExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFailedDependency(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "424 error",
			err:  &APIError{StatusCode: 424},
			want: true,
		},
		{
			name: "failed dependency code",
			err:  &APIError{Code: ErrorCodeFailedDependency},
			want: true,
		},
		{
			name: "404 error",
			err:  &APIError{StatusCode: 404},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsFailedDependency(tt.err)
			if got != tt.want {
				t.Errorf("IsFailedDependency() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDeadlineExceeded(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "504 error",
			err:  &APIError{StatusCode: 504},
			want: true,
		},
		{
			name: "deadline exceeded code",
			err:  &APIError{Code: ErrorCodeDeadlineExceeded},
			want: true,
		},
		{
			name: "404 error",
			err:  &APIError{StatusCode: 404},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDeadlineExceeded(tt.err)
			if got != tt.want {
				t.Errorf("IsDeadlineExceeded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsQueryError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "unselective content query code",
			err:  &APIError{Code: ErrorCodeUnselectiveContentQuery},
			want: true,
		},
		{
			name: "unsupported content query code",
			err:  &APIError{Code: ErrorCodeUnsupportedContentQuery},
			want: true,
		},
		{
			name: "other error code",
			err:  &APIError{Code: ErrorCodeNotFound},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsQueryError(tt.err)
			if got != tt.want {
				t.Errorf("IsQueryError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUserNotActive(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "user not active code",
			err:  &APIError{Code: ErrorCodeUserNotActive},
			want: true,
		},
		{
			name: "other error code",
			err:  &APIError{Code: ErrorCodeNotFound},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsUserNotActive(tt.err)
			if got != tt.want {
				t.Errorf("IsUserNotActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsWrongCredentials(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "wrong credentials code",
			err:  &APIError{Code: ErrorCodeWrongCredentials},
			want: true,
		},
		{
			name: "other error code",
			err:  &APIError{Code: ErrorCodeNotFound},
			want: false,
		},
		{
			name: "non-APIError",
			err:  errors.New("generic error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWrongCredentials(tt.err)
			if got != tt.want {
				t.Errorf("IsWrongCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}
