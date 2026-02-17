package client

import (
	"fmt"
	"time"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
	"go.uber.org/zap"
	"resty.dev/v3"
)

// Transport represents the HTTP transport layer for VirusTotal API.
// It provides methods for making HTTP requests to the VirusTotal API with built-in
// authentication, retry logic, and request/response logging.
// This is an internal component - users should use virustotal.NewClient() instead.
type Transport struct {
	client        *resty.Client
	logger        *zap.Logger
	authConfig    *AuthConfig
	tokenManager  *TokenManager
	BaseURL       string
	globalHeaders map[string]string
	userAgent     string
}

// NewTransport creates a new VirusTotal API transport.
// This is an internal function - users should use virustotal.NewClient() instead.
func NewTransport(apiKey string, options ...ClientOption) (*Transport, error) {

	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	authConfig := &AuthConfig{
		APIKey:     apiKey,
		APIVersion: DefaultAPIVersion,
	}

	// Format: "go-api-sdk-virustotal/1.0.0; gzip"
	// The "gzip" keyword helps with AppEngine content serving
	userAgent := fmt.Sprintf("%s/%s; gzip", UserAgentBase, Version)

	// Create resty client
	restyClient := resty.New()
	restyClient.SetTimeout(DefaultTimeout * time.Second)
	restyClient.SetRetryCount(MaxRetries)
	restyClient.SetRetryWaitTime(RetryWaitTime * time.Second)
	restyClient.SetRetryMaxWaitTime(RetryMaxWaitTime * time.Second)
	restyClient.SetHeader("User-Agent", userAgent)
	restyClient.SetHeader("Accept-Encoding", "gzip")

	// Create transport instance
	transport := &Transport{
		client:        restyClient,
		logger:        logger,
		authConfig:    authConfig,
		BaseURL:       DefaultBaseURL,
		globalHeaders: make(map[string]string),
		userAgent:     userAgent,
	}

	// Apply any additional options
	for _, option := range options {
		if err := option(transport); err != nil {
			return nil, fmt.Errorf("failed to apply client option: %w", err)
		}
	}

	// Define token refresh function
	// TODO: Implement actual VirusTotal token refresh API call when endpoint becomes available.
	refreshFunc := func(apiKey string) (string, time.Time, error) {
		// Placeholder implementation - replace with actual VirusTotal token API call
		// For now, this generates a token with the configured lifetime
		token := "vt-token-" + apiKey
		expiresAt := time.Now().Add(authConfig.TokenLifetime)

		logger.Debug("Token refresh called (placeholder implementation)",
			zap.Time("expires_at", expiresAt))

		return token, expiresAt, nil
	}

	// Setup token-based authentication
	tokenManager, err := SetupAuthentication(restyClient, authConfig, logger, refreshFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to setup authentication: %w", err)
	}
	transport.tokenManager = tokenManager

	restyClient.SetBaseURL(transport.BaseURL)

	logger.Info("VirusTotal API transport created",
		zap.String("base_url", transport.BaseURL),
		zap.String("api_version", authConfig.APIVersion),
		zap.Duration("token_lifetime", authConfig.TokenLifetime),
		zap.Duration("refresh_threshold", authConfig.RefreshThreshold))

	return transport, nil
}

// GetHTTPClient returns the underlying resty client
func (t *Transport) GetHTTPClient() *resty.Client {
	return t.client
}

// GetLogger returns the logger instance
func (t *Transport) GetLogger() *zap.Logger {
	return t.logger
}

// QueryBuilder creates a new query builder instance
func (t *Transport) QueryBuilder() interfaces.ServiceQueryBuilder {
	return NewQueryBuilder()
}

// GetTokenManager returns the token manager instance for advanced token operations
func (t *Transport) GetTokenManager() *TokenManager {
	return t.tokenManager
}

// GetTokenInfo returns current token status information for monitoring
func (t *Transport) GetTokenInfo() TokenInfo {
	if t.tokenManager == nil {
		return TokenInfo{}
	}
	return t.tokenManager.GetTokenInfo()
}

// ForceTokenRefresh forces an immediate token refresh
// This can be useful for testing or when you know the token needs to be refreshed
func (t *Transport) ForceTokenRefresh() error {
	if t.tokenManager == nil {
		return fmt.Errorf("token manager not initialized")
	}
	return t.tokenManager.ForceRefresh()
}
