package client

import (
	"fmt"
	"time"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
	"go.uber.org/zap"
	"resty.dev/v3"
)

// Client represents the HTTP client for VirusTotal API
type Client struct {
	client     *resty.Client
	logger     *zap.Logger
	authConfig *AuthConfig
	BaseURL    string
}

// NewClient creates a new VirusTotal API client
func NewClient(apiKey string, options ...ClientOption) (*Client, error) {
	// Create default logger
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	authConfig := &AuthConfig{
		APIKey:     apiKey,
		APIVersion: DefaultAPIVersion,
	}

	// Create resty client
	restyClient := resty.New()
	restyClient.SetTimeout(DefaultTimeout * time.Second)
	restyClient.SetRetryCount(MaxRetries)
	restyClient.SetRetryWaitTime(RetryWaitTime * time.Second)
	restyClient.SetRetryMaxWaitTime(RetryMaxWaitTime * time.Second)
	restyClient.SetHeader("User-Agent", UserAgent)

	// Create client instance
	client := &Client{
		client:     restyClient,
		logger:     logger,
		authConfig: authConfig,
		BaseURL:    DefaultBaseURL,
	}

	// Apply any additional options
	for _, option := range options {
		if err := option(client); err != nil {
			return nil, fmt.Errorf("failed to apply client option: %w", err)
		}
	}

	if err := SetupAuthentication(restyClient, authConfig, logger); err != nil {
		return nil, fmt.Errorf("failed to setup authentication: %w", err)
	}

	restyClient.SetBaseURL(client.BaseURL)

	logger.Info("VirusTotal API client created",
		zap.String("base_url", client.BaseURL),
		zap.String("api_version", authConfig.APIVersion))

	return client, nil
}

// GetHTTPClient returns the underlying resty client
func (c *Client) GetHTTPClient() *resty.Client {
	return c.client
}

// GetLogger returns the logger instance
func (c *Client) GetLogger() *zap.Logger {
	return c.logger
}

// QueryBuilder creates a new query builder instance
func (c *Client) QueryBuilder() interfaces.ServiceQueryBuilder {
	return NewQueryBuilder()
}
