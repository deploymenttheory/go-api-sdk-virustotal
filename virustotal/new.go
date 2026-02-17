package virustotal

import (
	"fmt"
	"os"

	"go.uber.org/zap"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/analyses"
	attacktactics "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/attack_tactics"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/comments"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/domains"
	filebehaviours "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/file_behaviours"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
	ipaddresses "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/ip_addresses"
	popularthreatcategories "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/popular_threat_categories"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/urls"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/vt_enterprise/collections"
	searchandmetadata "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/vt_enterprise/search_and_metadata"
	yararules "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/vt_hunting/yara_rules"
)

// Client is the main entry point for the VirusTotal API SDK.
// It aggregates all service clients and provides a unified interface.
// Users should interact with the API exclusively through the provided service methods.
type Client struct {
	// transport is the internal HTTP transport layer (not exposed to users)
	transport *client.Transport

	// IOC Reputation & Enrichment Services
	Analyses                *analyses.Service
	AttackTactics           *attacktactics.Service
	Comments                *comments.Service
	Domains                 *domains.Service
	FileBehaviours          *filebehaviours.Service
	Files                   *files.Service
	IPAddresses             *ipaddresses.Service
	PopularThreatCategories *popularthreatcategories.Service
	URLs                    *urls.Service

	// VT Enterprise Services
	Collections       *collections.Service
	SearchAndMetadata *searchandmetadata.Service

	// VT Hunting Services
	YaraRules *yararules.Service
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

	transport, err := client.NewTransport(apiKey, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP transport: %w", err)
	}

	// Initialize vt sdk service clients
	c := &Client{
		transport:               transport,
		Analyses:                analyses.NewService(transport),
		AttackTactics:           attacktactics.NewService(transport),
		Comments:                comments.NewService(transport),
		Domains:                 domains.NewService(transport),
		FileBehaviours:          filebehaviours.NewService(transport),
		Files:                   files.NewService(transport),
		IPAddresses:             ipaddresses.NewService(transport),
		PopularThreatCategories: popularthreatcategories.NewService(transport),
		URLs:                    urls.NewService(transport),
		Collections:             collections.NewService(transport),
		SearchAndMetadata:       searchandmetadata.NewService(transport),
		YaraRules:               yararules.NewService(transport),
	}

	return c, nil
}

// NewClientFromEnv creates a new client using environment variables
//
// Required environment variables:
//   - VT_API_KEY: The VirusTotal API key
//
// Optional environment variables:
//   - VIRUSTOTAL_BASE_URL: Custom base URL (defaults to https://www.virustotal.com/api/v3)
//
// Example:
//
//	client, err := virustotal.NewClientFromEnv()
func NewClientFromEnv(options ...client.ClientOption) (*Client, error) {
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("VT_API_KEY environment variable is required")
	}

	// Check for optional environment variables and append to options
	if baseURL := os.Getenv("VIRUSTOTAL_BASE_URL"); baseURL != "" {
		options = append(options, client.WithBaseURL(baseURL))
	}

	return NewClient(apiKey, options...)
}

// GetLogger returns the configured zap logger instance.
// Use this to add custom logging within your application using the same logger.
//
// Returns:
//   - *zap.Logger: The configured logger instance
func (c *Client) GetLogger() *zap.Logger {
	return c.transport.GetLogger()
}

// GetTokenManager returns the token manager instance for advanced token operations.
// This allows access to low-level token management functionality when needed.
//
// Returns:
//   - *client.TokenManager: The token manager instance
func (c *Client) GetTokenManager() *client.TokenManager {
	return c.transport.GetTokenManager()
}

// GetTokenInfo returns current token status information for monitoring.
// This includes the token value, expiration time, and whether it's expired.
//
// Returns:
//   - client.TokenInfo: Current token information
func (c *Client) GetTokenInfo() client.TokenInfo {
	return c.transport.GetTokenInfo()
}

// ForceTokenRefresh forces an immediate token refresh.
// This can be useful for testing or when you know the token needs to be refreshed.
//
// Returns:
//   - error: Any error encountered during token refresh
func (c *Client) ForceTokenRefresh() error {
	return c.transport.ForceTokenRefresh()
}
