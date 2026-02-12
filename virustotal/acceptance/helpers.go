package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// SkipIfAPIKeyNotSet skips the test if the API key is not configured
func SkipIfAPIKeyNotSet(t *testing.T) {
	t.Helper()
	if !IsAPIKeySet() {
		t.Skip("VT_API_KEY not set, skipping acceptance test")
	}
}

// RequireClient ensures the shared client is initialized
// Skips the test if the API key is not set or client initialization fails
func RequireClient(t *testing.T) {
	t.Helper()
	SkipIfAPIKeyNotSet(t)

	if Client == nil {
		err := InitClient()
		require.NoError(t, err, "Failed to initialize VirusTotal client")
	}
}

// RateLimitedTest wraps a test function with rate limiting
// Automatically sleeps after test execution to respect API rate limits
func RateLimitedTest(t *testing.T, testFunc func(t *testing.T)) {
	t.Helper()
	defer func() {
		if Config.Verbose {
			t.Logf("Rate limiting: sleeping for %v", Config.RateLimitDelay)
		}
		time.Sleep(Config.RateLimitDelay)
	}()
	testFunc(t)
}

// NewContext creates a context with timeout for acceptance tests
func NewContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), Config.RequestTimeout)
}

// LogResponse logs the response details if verbose mode is enabled
func LogResponse(t *testing.T, message string, details ...interface{}) {
	t.Helper()
	if Config.Verbose {
		if len(details) > 0 {
			t.Logf(message, details...)
		} else {
			t.Log(message)
		}
	}
}

// AssertNoError is a helper that fails the test if an error occurs
// and logs additional context in verbose mode
func AssertNoError(t *testing.T, err error, msgAndArgs ...interface{}) {
	t.Helper()
	if err != nil {
		if Config.Verbose {
			t.Logf("Error occurred: %v", err)
		}
	}
	require.NoError(t, err, msgAndArgs...)
}

// AssertNotNil is a helper that fails the test if the object is nil
func AssertNotNil(t *testing.T, object interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	require.NotNil(t, object, msgAndArgs...)
}

// Cleanup registers a cleanup function that respects the SkipCleanup flag
func Cleanup(t *testing.T, cleanupFunc func()) {
	t.Helper()
	if !Config.SkipCleanup {
		t.Cleanup(cleanupFunc)
	} else if Config.Verbose {
		t.Log("Skipping cleanup due to VT_SKIP_CLEANUP=true")
	}
}
