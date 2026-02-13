package client

import (
	"net/http"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

// Response helper functions for working with interfaces.Response

// IsResponseSuccess returns true if the response status code is 2xx
func IsResponseSuccess(resp *interfaces.Response) bool {
	if resp == nil {
		return false
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// IsResponseError returns true if the response status code is 4xx or 5xx
func IsResponseError(resp *interfaces.Response) bool {
	if resp == nil {
		return false
	}
	return resp.StatusCode >= 400
}

// GetResponseHeader returns a header value from the response by key (case-insensitive)
func GetResponseHeader(resp *interfaces.Response, key string) string {
	if resp == nil || resp.Headers == nil {
		return ""
	}
	return resp.Headers.Get(key)
}

// GetResponseHeaders returns all headers from the response
func GetResponseHeaders(resp *interfaces.Response) http.Header {
	if resp == nil {
		return make(http.Header)
	}
	return resp.Headers
}

// GetRateLimitHeaders extracts common VirusTotal rate limit headers from the response
// Returns: (quota limit, quota remaining, quota reset time, retry-after)
func GetRateLimitHeaders(resp *interfaces.Response) (limit, remaining, reset, retryAfter string) {
	if resp == nil {
		return
	}
	return resp.Headers.Get("X-Api-Quota-Limit"),
		resp.Headers.Get("X-Api-Quota-Remaining"),
		resp.Headers.Get("X-Api-Quota-Reset"),
		resp.Headers.Get("Retry-After")
}
