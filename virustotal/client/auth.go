package client

import (
	"fmt"
	"sync"

	"go.uber.org/zap"
	"resty.dev/v3"
)

// AuthConfig holds authentication configuration for the VirusTotal API
type AuthConfig struct {
	// APIKey is the VirusTotal API key
	APIKey string

	// APIVersion is the optional API version (defaults to v3)
	APIVersion string
}

// AuthManager handles thread-safe API key management
type AuthManager struct {
	authConfig *AuthConfig
	logger     *zap.Logger
	mu         sync.RWMutex
}

// NewAuthManager creates a new auth manager
func NewAuthManager(authConfig *AuthConfig, logger *zap.Logger) *AuthManager {
	return &AuthManager{
		authConfig: authConfig,
		logger:     logger,
	}
}

// Validate checks if the auth configuration is valid
func (a *AuthConfig) Validate() error {
	if a.APIKey == "" {
		return fmt.Errorf("API key is required")
	}
	return nil
}

// GetAPIKey returns the current API key in a thread-safe manner
func (am *AuthManager) GetAPIKey() (string, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if am.authConfig.APIKey == "" {
		return "", fmt.Errorf("API key is not set")
	}

	return am.authConfig.APIKey, nil
}

// UpdateAPIKey updates the API key in a thread-safe manner
// This allows for runtime API key rotation without recreating the client
func (am *AuthManager) UpdateAPIKey(newAPIKey string) error {
	if newAPIKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	oldKey := am.authConfig.APIKey
	am.authConfig.APIKey = newAPIKey

	am.logger.Info("API key updated successfully",
		zap.Bool("had_previous_key", oldKey != ""))

	return nil
}

// ValidateAPIKey validates that an API key is currently set
func (am *AuthManager) ValidateAPIKey() error {
	am.mu.RLock()
	defer am.mu.RUnlock()

	return am.authConfig.Validate()
}

// GetAPIVersion returns the API version
func (am *AuthManager) GetAPIVersion() string {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if am.authConfig.APIVersion == "" {
		return DefaultAPIVersion
	}
	return am.authConfig.APIVersion
}

// SetupAuthentication configures the resty client with API key authentication and middleware
func SetupAuthentication(client *resty.Client, authConfig *AuthConfig, logger *zap.Logger) (*AuthManager, error) {
	if err := authConfig.Validate(); err != nil {
		logger.Error("Authentication validation failed", zap.Error(err))
		return nil, fmt.Errorf("authentication validation failed: %w", err)
	}

	// Create auth manager for thread-safe key management
	authManager := NewAuthManager(authConfig, logger)

	// Set initial API key header
	client.SetHeader(APIKeyHeader, authConfig.APIKey)

	// Add request middleware to validate API key before each request
	// This ensures the key is always present and allows for runtime key rotation
	client.AddRequestMiddleware(func(c *resty.Client, req *resty.Request) error {
		apiKey, err := authManager.GetAPIKey()
		if err != nil {
			logger.Error("Failed to get valid API key for request", zap.Error(err))
			return fmt.Errorf("failed to get valid API key: %w", err)
		}
		// Update the request header with current API key
		req.SetHeader(APIKeyHeader, apiKey)
		return nil
	})

	apiVersion := authConfig.APIVersion
	if apiVersion == "" {
		apiVersion = DefaultAPIVersion
	}

	logger.Info("Authentication configured successfully with middleware validation",
		zap.String("api_version", apiVersion))

	return authManager, nil
}
