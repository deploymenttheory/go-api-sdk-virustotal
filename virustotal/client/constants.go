package client

const (
	// DefaultBaseURL is the default base URL for the VirusTotal API
	DefaultBaseURL = "https://www.virustotal.com/api/v3"

	// DefaultAPIVersion is the API version
	DefaultAPIVersion = "v3"

	// APIKeyHeader is the header name for the API key
	APIKeyHeader = "x-apikey"

	// UserAgent is the user agent string for API requests
	UserAgent = "go-api-sdk-virustotal/1.0.0"

	// DefaultTimeout is the default HTTP client timeout in seconds
	DefaultTimeout = 120

	// MaxRetries is the maximum number of retries for failed requests
	MaxRetries = 3

	// RetryWaitTime is the wait time between retries in seconds
	RetryWaitTime = 2

	// RetryMaxWaitTime is the maximum wait time between retries in seconds
	RetryMaxWaitTime = 10
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
