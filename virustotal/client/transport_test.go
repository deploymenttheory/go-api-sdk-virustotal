package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestNewTransport_Success(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	transport, err := NewTransport(apiKey)
	
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.NotNil(t, transport.client)
	assert.NotNil(t, transport.logger)
	assert.NotNil(t, transport.authConfig)
	assert.Equal(t, apiKey, transport.authConfig.APIKey)
	assert.Equal(t, DefaultBaseURL, transport.BaseURL)
	assert.Equal(t, DefaultAPIVersion, transport.authConfig.APIVersion)
	assert.NotEmpty(t, transport.userAgent)
	assert.NotNil(t, transport.globalHeaders)
}

func TestNewTransport_EmptyAPIKey(t *testing.T) {
	transport, err := NewTransport("")
	
	require.Error(t, err)
	assert.Nil(t, transport)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestNewTransport_WithOptions(t *testing.T) {
	apiKey := "test-api-key-12345"
	customBaseURL := "https://custom.virustotal.com/api/v3"
	customVersion := "v4"
	
	transport, err := NewTransport(apiKey,
		WithBaseURL(customBaseURL),
		WithAPIVersion(customVersion),
		WithTimeout(60*time.Second),
		WithRetryCount(5),
	)
	
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.Equal(t, customBaseURL, transport.BaseURL)
	assert.Equal(t, customVersion, transport.authConfig.APIVersion)
}

func TestNewTransport_WithCustomLogger(t *testing.T) {
	apiKey := "test-api-key-12345"
	customLogger := zaptest.NewLogger(t)
	
	transport, err := NewTransport(apiKey, WithLogger(customLogger))
	
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.Equal(t, customLogger, transport.logger)
}

func TestNewTransport_WithGlobalHeaders(t *testing.T) {
	apiKey := "test-api-key-12345"
	headers := map[string]string{
		"X-Custom-Header": "custom-value",
		"X-Test-Header":   "test-value",
	}
	
	transport, err := NewTransport(apiKey, WithGlobalHeaders(headers))
	
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.Equal(t, "custom-value", transport.globalHeaders["X-Custom-Header"])
	assert.Equal(t, "test-value", transport.globalHeaders["X-Test-Header"])
}

func TestNewTransport_WithDebug(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	transport, err := NewTransport(apiKey, WithDebug())
	
	require.NoError(t, err)
	require.NotNil(t, transport)
	// Debug mode should be enabled (we can't directly test the private debug field)
	// Just verify the transport was created successfully
	assert.NotNil(t, transport.client)
}

func TestTransport_GetHTTPClient(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	transport, err := NewTransport(apiKey)
	require.NoError(t, err)
	
	httpClient := transport.GetHTTPClient()
	
	assert.NotNil(t, httpClient)
	assert.Equal(t, transport.client, httpClient)
}

func TestTransport_GetLogger(t *testing.T) {
	apiKey := "test-api-key-12345"
	customLogger := zaptest.NewLogger(t)
	
	transport, err := NewTransport(apiKey, WithLogger(customLogger))
	require.NoError(t, err)
	
	logger := transport.GetLogger()
	
	assert.NotNil(t, logger)
	assert.Equal(t, customLogger, logger)
}

func TestTransport_QueryBuilder(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	transport, err := NewTransport(apiKey)
	require.NoError(t, err)
	
	queryBuilder := transport.QueryBuilder()
	
	assert.NotNil(t, queryBuilder)
	// Verify it's a functioning query builder
	params := queryBuilder.
		AddString("key", "value").
		AddInt("count", 10).
		Build()
	
	assert.Equal(t, "value", params["key"])
	assert.Equal(t, "10", params["count"])
}

func TestNewTransport_MultipleOptions(t *testing.T) {
	apiKey := "test-api-key-12345"
	customBaseURL := "https://custom.virustotal.com/api/v3"
	customVersion := "v4"
	timeout := 90 * time.Second
	retryCount := 5
	headers := map[string]string{
		"X-Custom": "value",
	}
	
	transport, err := NewTransport(apiKey,
		WithBaseURL(customBaseURL),
		WithAPIVersion(customVersion),
		WithTimeout(timeout),
		WithRetryCount(retryCount),
		WithGlobalHeaders(headers),
		WithDebug(),
	)
	
	require.NoError(t, err)
	require.NotNil(t, transport)
	
	assert.Equal(t, customBaseURL, transport.BaseURL)
	assert.Equal(t, customVersion, transport.authConfig.APIVersion)
	assert.Equal(t, "value", transport.globalHeaders["X-Custom"])
	// Debug mode is set but can't be directly tested (private field)
	assert.NotNil(t, transport.client)
}

func TestNewTransport_InvalidOption(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	// Create an option that returns an error
	invalidOption := func(t *Transport) error {
		return assert.AnError
	}
	
	transport, err := NewTransport(apiKey, invalidOption)
	
	require.Error(t, err)
	assert.Nil(t, transport)
	assert.Contains(t, err.Error(), "failed to apply client option")
}

func TestTransport_UserAgent(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	transport, err := NewTransport(apiKey)
	require.NoError(t, err)
	
	assert.Contains(t, transport.userAgent, UserAgentBase)
	assert.Contains(t, transport.userAgent, Version)
	assert.Contains(t, transport.userAgent, "gzip")
}

func TestTransport_DefaultConfiguration(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	transport, err := NewTransport(apiKey)
	require.NoError(t, err)
	
	// Verify defaults are applied
	assert.Equal(t, DefaultBaseURL, transport.BaseURL)
	assert.Equal(t, DefaultAPIVersion, transport.authConfig.APIVersion)
	
	// Verify resty client defaults
	httpClient := transport.GetHTTPClient()
	assert.NotNil(t, httpClient)
}

func TestTransport_BaseURLSetCorrectly(t *testing.T) {
	apiKey := "test-api-key-12345"
	customBaseURL := "https://custom.example.com/api/v3"
	
	transport, err := NewTransport(apiKey, WithBaseURL(customBaseURL))
	require.NoError(t, err)
	
	// Verify the base URL is set on both the transport and resty client
	assert.Equal(t, customBaseURL, transport.BaseURL)
	assert.Equal(t, customBaseURL, transport.client.BaseURL())
}
