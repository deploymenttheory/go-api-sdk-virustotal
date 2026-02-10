package virustotal

import (
	"fmt"
	"os"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ipaddresses"
)

// Client is the main entry point for the VirusTotal API SDK
// It aggregates all service clients and provides a unified interface
type Client struct {
	*client.Client

	// Services
	IPAddresses *ipaddresses.Service
}

// NewClient creates a new VirusTotal API client
//
// Parameters:
//   - apiKey: The VirusTotal API key
//   - options: Optional client configuration options
//
// Example:
//
//	client, err := virustotal.NewClient(
//	    "your-api-key",
//	    virustotal.WithDebug(),
//	)
func NewClient(apiKey string, options ...client.ClientOption) (*Client, error) {
	// Create base HTTP client
	httpClient, err := client.NewClient(apiKey, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Initialize service clients
	c := &Client{
		Client:      httpClient,
		IPAddresses: ipaddresses.NewService(httpClient),
	}

	return c, nil
}

// NewClientFromEnv creates a new client using environment variables
//
// Required environment variables:
//   - VIRUSTOTAL_API_KEY: The VirusTotal API key
//
// Optional environment variables:
//   - VIRUSTOTAL_BASE_URL: Custom base URL (defaults to https://www.virustotal.com/api/v3)
//
// Example:
//
//	client, err := virustotal.NewClientFromEnv()
func NewClientFromEnv(options ...client.ClientOption) (*Client, error) {
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("VIRUSTOTAL_API_KEY environment variable is required")
	}

	// Check for optional environment variables and append to options
	if baseURL := os.Getenv("VIRUSTOTAL_BASE_URL"); baseURL != "" {
		options = append(options, client.WithBaseURL(baseURL))
	}

	return NewClient(apiKey, options...)
}
