package client

import (
	"fmt"

	"go.uber.org/zap"
	"resty.dev/v3"
)

// AuthConfig holds authentication configuration for the VirusTotal API
type AuthConfig struct {
	// APIKey is the VirusTotal API key
	APIKey string

	// APIVersion is the API version
	APIVersion string
}

// Validate checks if the auth configuration is valid
func (a *AuthConfig) Validate() error {
	if a.APIKey == "" {
		return fmt.Errorf("API key is required")
	}

	return nil
}

// SetupAuthentication configures the resty client with API key-based authentication
// per VirusTotal documentation: https://docs.virustotal.com/reference/authentication
func SetupAuthentication(client *resty.Client, authConfig *AuthConfig, logger *zap.Logger) error {
	if err := authConfig.Validate(); err != nil {
		logger.Error("Authentication validation failed", zap.Error(err))
		return fmt.Errorf("authentication validation failed: %w", err)
	}

	// Set the x-apikey header per VirusTotal API documentation
	client.SetHeader("x-apikey", authConfig.APIKey)

	apiVersion := authConfig.APIVersion
	if apiVersion == "" {
		apiVersion = DefaultAPIVersion
	}

	logger.Info("VirusTotal API authentication configured",
		zap.String("api_version", apiVersion))

	return nil
}
