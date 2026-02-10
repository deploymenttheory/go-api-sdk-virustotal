package ipaddresses

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// IPAddressesServiceInterface defines the interface for IP address operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	IPAddressesServiceInterface interface {
		// GetIPAddressReport retrieves information about an IP address
		//
		// Returns IP address reputation data including network information, ASN, country, malware detection stats,
		// WHOIS data, popularity ranks, and community votes. Optionally include relationships like comments,
		// resolutions, historical SSL certificates, and related threat actors.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/ip-info
		GetIPAddressReport(ctx context.Context, ip string, opts *RequestQueryOptions) (*IPAddressResponse, error)
	}

	// Service handles communication with the IP addresses
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	Service struct {
		client interfaces.HTTPClient
	}
)

// Ensure Service implements IPAddressesServiceInterface
var _ IPAddressesServiceInterface = (*Service)(nil)

// NewService creates a new IP addresses service
func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// GetIPAddressReport retrieves information about an IP address
// URL: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
//
// Example cURL:
//
//	curl -X GET \
//	  -H "x-apikey: YOUR_API_KEY" \
//	  -H "Accept: application/json" \
//	  "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
func (s *Service) GetIPAddressReport(ctx context.Context, ip string, opts *RequestQueryOptions) (*IPAddressResponse, error) {
	if ip == "" {
		return nil, fmt.Errorf("ip address is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointIPAddresses, ip)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)
	if opts != nil && opts.Relationships != "" {
		queryParams["relationships"] = opts.Relationships
	}

	var result IPAddressResponse
	err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
