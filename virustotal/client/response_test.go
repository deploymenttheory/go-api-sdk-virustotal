package client

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"resty.dev/v3"
)

// newTestRestyResponse creates a *resty.Response from an http.Response for use in tests.
func newTestRestyResponse(statusCode int, headers http.Header) *resty.Response {
	httpResp := &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader("")),
	}

	c := resty.New()
	req := c.R()
	restyResp := &resty.Response{
		RawResponse: httpResp,
		Request:     req,
	}
	return restyResp
}

func TestIsResponseSuccess(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		isNil      bool
		expected   bool
	}{
		{
			name:     "nil response",
			isNil:    true,
			expected: false,
		},
		{
			name:       "200 OK",
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "201 Created",
			statusCode: 201,
			expected:   true,
		},
		{
			name:       "299 edge case",
			statusCode: 299,
			expected:   true,
		},
		{
			name:       "400 Bad Request",
			statusCode: 400,
			expected:   false,
		},
		{
			name:       "404 Not Found",
			statusCode: 404,
			expected:   false,
		},
		{
			name:       "500 Internal Server Error",
			statusCode: 500,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *resty.Response
			if !tt.isNil {
				resp = newTestRestyResponse(tt.statusCode, nil)
			}
			result := IsResponseSuccess(resp)
			if result != tt.expected {
				t.Errorf("IsResponseSuccess() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsResponseError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		isNil      bool
		expected   bool
	}{
		{
			name:     "nil response",
			isNil:    true,
			expected: false,
		},
		{
			name:       "200 OK",
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "400 Bad Request",
			statusCode: 400,
			expected:   true,
		},
		{
			name:       "404 Not Found",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "429 Too Many Requests",
			statusCode: 429,
			expected:   true,
		},
		{
			name:       "500 Internal Server Error",
			statusCode: 500,
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *resty.Response
			if !tt.isNil {
				resp = newTestRestyResponse(tt.statusCode, nil)
			}
			result := IsResponseError(resp)
			if result != tt.expected {
				t.Errorf("IsResponseError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetResponseHeader(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Custom-Header", "test-value")

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		isNil      bool
		key        string
		expected   string
	}{
		{
			name:     "nil response",
			isNil:    true,
			key:      "Content-Type",
			expected: "",
		},
		{
			name:       "nil headers",
			statusCode: 200,
			headers:    nil,
			key:        "Content-Type",
			expected:   "",
		},
		{
			name:       "existing header",
			statusCode: 200,
			headers:    headers,
			key:        "Content-Type",
			expected:   "application/json",
		},
		{
			name:       "case insensitive header",
			statusCode: 200,
			headers:    headers,
			key:        "content-type",
			expected:   "application/json",
		},
		{
			name:       "missing header",
			statusCode: 200,
			headers:    headers,
			key:        "Missing-Header",
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *resty.Response
			if !tt.isNil {
				resp = newTestRestyResponse(tt.statusCode, tt.headers)
			}
			result := GetResponseHeader(resp, tt.key)
			if result != tt.expected {
				t.Errorf("GetResponseHeader() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetRateLimitHeaders(t *testing.T) {
	tests := []struct {
		name              string
		headers           http.Header
		isNil             bool
		expectedLimit     string
		expectedRemaining string
		expectedReset     string
		expectedRetry     string
	}{
		{
			name:              "nil response",
			isNil:             true,
			expectedLimit:     "",
			expectedRemaining: "",
			expectedReset:     "",
			expectedRetry:     "",
		},
		{
			name: "rate limit headers present",
			headers: http.Header{
				"X-Api-Quota-Limit":     []string{"500"},
				"X-Api-Quota-Remaining": []string{"450"},
				"X-Api-Quota-Reset":     []string{"1640000000"},
				"Retry-After":           []string{"60"},
			},
			expectedLimit:     "500",
			expectedRemaining: "450",
			expectedReset:     "1640000000",
			expectedRetry:     "60",
		},
		{
			name: "partial rate limit headers",
			headers: http.Header{
				"X-Api-Quota-Limit":     []string{"500"},
				"X-Api-Quota-Remaining": []string{"450"},
			},
			expectedLimit:     "500",
			expectedRemaining: "450",
			expectedReset:     "",
			expectedRetry:     "",
		},
		{
			name:              "no rate limit headers",
			headers:           make(http.Header),
			expectedLimit:     "",
			expectedRemaining: "",
			expectedReset:     "",
			expectedRetry:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *resty.Response
			if !tt.isNil {
				resp = newTestRestyResponse(200, tt.headers)
			}
			limit, remaining, reset, retry := GetRateLimitHeaders(resp)
			if limit != tt.expectedLimit {
				t.Errorf("limit = %v, want %v", limit, tt.expectedLimit)
			}
			if remaining != tt.expectedRemaining {
				t.Errorf("remaining = %v, want %v", remaining, tt.expectedRemaining)
			}
			if reset != tt.expectedReset {
				t.Errorf("reset = %v, want %v", reset, tt.expectedReset)
			}
			if retry != tt.expectedRetry {
				t.Errorf("retry = %v, want %v", retry, tt.expectedRetry)
			}
		})
	}
}
