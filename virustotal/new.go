package virustotal

import (
	"fmt"
	"os"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/analyses"
	attacktactics "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/attack_tactics"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/comments"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/domains"
	filebehaviours "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/file_behaviours"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/files"
	ipaddresses "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ip_addresses"
	popularthreatcategories "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/popular_threat_categories"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/urls"
)

// Client is the main entry point for the VirusTotal API SDK
// It aggregates all service clients and provides a unified interface
type Client struct {
	*client.Client

	// Services
	Analyses                *analyses.Service
	AttackTactics           *attacktactics.Service
	Comments                *comments.Service
	Domains                 *domains.Service
	FileBehaviours          *filebehaviours.Service
	Files                   *files.Service
	IPAddresses             *ipaddresses.Service
	PopularThreatCategories *popularthreatcategories.Service
	URLs                    *urls.Service
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
		Client:                  httpClient,
		Analyses:                analyses.NewService(httpClient),
		AttackTactics:           attacktactics.NewService(httpClient),
		Comments:                comments.NewService(httpClient),
		Domains:                 domains.NewService(httpClient),
		FileBehaviours:          filebehaviours.NewService(httpClient),
		Files:                   files.NewService(httpClient),
		IPAddresses:             ipaddresses.NewService(httpClient),
		PopularThreatCategories: popularthreatcategories.NewService(httpClient),
		URLs:                    urls.NewService(httpClient),
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
