package client

import "time"

const (
	// DefaultBaseURL is the default base URL for the VirusTotal API
	DefaultBaseURL = "https://www.virustotal.com/api/v3"

	// DefaultAPIVersion is the API version
	DefaultAPIVersion = "v3"

	// APIKeyHeader is the header name for the API key
	APIKeyHeader = "x-apikey"

	// UserAgentBase is the base user agent string prefix
	UserAgentBase = "go-api-sdk-virustotal"

	// DefaultTimeout is the default HTTP client timeout in seconds
	DefaultTimeout = 120

	// MaxRetries is the maximum number of retries for failed requests
	MaxRetries = 3

	// RetryWaitTime is the wait time between retries in seconds
	RetryWaitTime = 2

	// RetryMaxWaitTime is the maximum wait time between retries in seconds
	RetryMaxWaitTime = 10

	// DefaultTokenLifetime is how long a token is valid (1 hour)
	// I can't find a documented value for this, so I'm using 1 hour as a default
	DefaultTokenLifetime = 3600 * time.Second

	// DefaultRefreshThreshold - refresh token if less than this time remains (5 minutes)
	DefaultRefreshThreshold = 300 * time.Second

	// MinimumRefreshThreshold - minimum time before expiry to allow refresh (1 minute)
	MinimumRefreshThreshold = 60 * time.Second
)

// Response format constants
const (
	FormatJSON = "json"
)

// HTTP headers
const (
	ContentTypeJSON = "application/json"
	AcceptJSON      = "application/json"
)
