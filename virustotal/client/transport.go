package client

import (
	"context"
	"fmt"
	"time"

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

	// Setup API key-based authentication
	if err := SetupAuthentication(restyClient, authConfig, logger); err != nil {
		return nil, fmt.Errorf("failed to setup authentication: %w", err)
	}

	restyClient.SetBaseURL(transport.BaseURL)

	logger.Info("VirusTotal API transport created",
		zap.String("base_url", transport.BaseURL),
		zap.String("api_version", authConfig.APIVersion))

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
func (t *Transport) QueryBuilder() ServiceQueryBuilder {
	return NewQueryBuilder()
}

// NewRequest returns a RequestBuilder for this transport.
func (t *Transport) NewRequest(ctx context.Context) *RequestBuilder {
	req := t.client.R().SetContext(ctx)

	// Apply global headers
	for k, v := range t.globalHeaders {
		if v != "" {
			req.SetHeader(k, v)
		}
	}

	return &RequestBuilder{
		req:      req,
		executor: t,
	}
}
