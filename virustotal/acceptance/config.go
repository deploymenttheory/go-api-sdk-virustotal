package acceptance

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
)

// TestConfig holds configuration for acceptance tests
type TestConfig struct {
	APIKey          string
	BaseURL         string
	RateLimitDelay  time.Duration
	RequestTimeout  time.Duration
	SkipCleanup     bool
	Verbose         bool
	KnownAnalysisID string
	KnownFileHash   string
	KnownDomain     string
	KnownIPAddress  string
	KnownURL        string
}

var (
	// Config is the global test configuration
	Config *TestConfig
	// Client is the shared VirusTotal client for acceptance tests
	Client *client.Client
)

// init initializes the test configuration from environment variables
func init() {
	Config = &TestConfig{
		APIKey:          getEnv("VT_API_KEY", ""),
		BaseURL:         getEnv("VT_BASE_URL", "https://www.virustotal.com/api/v3"),
		RateLimitDelay:  getDurationEnv("VT_RATE_LIMIT_DELAY", 2*time.Second),
		RequestTimeout:  getDurationEnv("VT_REQUEST_TIMEOUT", 30*time.Second),
		SkipCleanup:     getBoolEnv("VT_SKIP_CLEANUP", false),
		Verbose:         getBoolEnv("VT_VERBOSE", false),
		KnownAnalysisID: getEnv("VT_TEST_ANALYSIS_ID", "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="),
		KnownFileHash:   getEnv("VT_TEST_FILE_HASH", "44d88612fea8a8f36de82e1278abb02f"), // EICAR test file
		KnownDomain:     getEnv("VT_TEST_DOMAIN", "google.com"),
		KnownIPAddress:  getEnv("VT_TEST_IP", "8.8.8.8"),
		KnownURL:        getEnv("VT_TEST_URL", "https://www.google.com"),
	}
}

// InitClient initializes the shared VirusTotal client
// Returns an error if the API key is not set or client creation fails
func InitClient() error {
	if Config.APIKey == "" {
		return fmt.Errorf("VT_API_KEY environment variable is not set")
	}

	var err error
	Client, err = client.NewClient(
		Config.APIKey,
		client.WithBaseURL(Config.BaseURL),
		client.WithTimeout(Config.RequestTimeout),
	)
	if err != nil {
		return fmt.Errorf("failed to create VirusTotal client: %w", err)
	}

	if Config.Verbose {
		log.Printf("Acceptance test client initialized with base URL: %s", Config.BaseURL)
	}

	return nil
}

// IsAPIKeySet returns true if the API key is configured
func IsAPIKeySet() bool {
	return Config.APIKey != ""
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getBoolEnv retrieves a boolean environment variable or returns a default value
func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			log.Printf("Warning: invalid boolean value for %s: %s, using default: %v", key, value, defaultValue)
			return defaultValue
		}
		return parsed
	}
	return defaultValue
}

// getDurationEnv retrieves a duration environment variable or returns a default value
func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			log.Printf("Warning: invalid duration value for %s: %s, using default: %v", key, value, defaultValue)
			return defaultValue
		}
		return parsed
	}
	return defaultValue
}
