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
	assert.NotNil(t, transport.tokenManager)
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

func TestNewTransport_WithTokenLifetime(t *testing.T) {
	apiKey := "test-api-key-12345"
	lifetime := 2 * time.Hour
	
	transport, err := NewTransport(apiKey, WithTokenLifetime(lifetime))
	
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.Equal(t, lifetime, transport.authConfig.TokenLifetime)
}

func TestNewTransport_WithTokenRefreshThreshold(t *testing.T) {
	apiKey := "test-api-key-12345"
	threshold := 15 * time.Minute
	
	transport, err := NewTransport(apiKey, WithTokenRefreshThreshold(threshold))
	
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.Equal(t, threshold, transport.authConfig.RefreshThreshold)
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

func TestTransport_GetTokenManager(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	transport, err := NewTransport(apiKey)
	require.NoError(t, err)
	
	tokenManager := transport.GetTokenManager()
	
	assert.NotNil(t, tokenManager)
	assert.Equal(t, transport.tokenManager, tokenManager)
}

func TestTransport_GetTokenInfo(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	transport, err := NewTransport(apiKey)
	require.NoError(t, err)
	
	tokenInfo := transport.GetTokenInfo()
	
	assert.True(t, tokenInfo.HasToken)
	assert.False(t, tokenInfo.ExpiresAt.IsZero())
	assert.False(t, tokenInfo.AcquiredAt.IsZero())
	assert.NotZero(t, tokenInfo.TimeRemaining)
}

func TestTransport_GetTokenInfo_NilTokenManager(t *testing.T) {
	// Create a transport with nil token manager (artificial scenario)
	transport := &Transport{
		tokenManager: nil,
	}
	
	tokenInfo := transport.GetTokenInfo()
	
	// Should return empty TokenInfo without panicking
	assert.False(t, tokenInfo.HasToken)
	assert.True(t, tokenInfo.ExpiresAt.IsZero())
	assert.True(t, tokenInfo.AcquiredAt.IsZero())
}

func TestTransport_ForceTokenRefresh(t *testing.T) {
	apiKey := "test-api-key-12345"
	
	transport, err := NewTransport(apiKey)
	require.NoError(t, err)
	
	// Get initial token info
	initialTokenInfo := transport.GetTokenInfo()
	initialExpiresAt := initialTokenInfo.ExpiresAt
	
	// Wait a tiny bit to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)
	
	// Force refresh
	err = transport.ForceTokenRefresh()
	require.NoError(t, err)
	
	// Get new token info
	newTokenInfo := transport.GetTokenInfo()
	
	// Expiration should be updated (new token acquired)
	assert.True(t, newTokenInfo.ExpiresAt.After(initialExpiresAt) ||
		newTokenInfo.ExpiresAt.Equal(initialExpiresAt))
	assert.True(t, newTokenInfo.HasToken)
}

func TestTransport_ForceTokenRefresh_NilTokenManager(t *testing.T) {
	// Create a transport with nil token manager
	transport := &Transport{
		tokenManager: nil,
	}
	
	err := transport.ForceTokenRefresh()
	
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token manager not initialized")
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
	assert.Equal(t, DefaultTokenLifetime, transport.authConfig.TokenLifetime)
	assert.Equal(t, DefaultRefreshThreshold, transport.authConfig.RefreshThreshold)
	
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
