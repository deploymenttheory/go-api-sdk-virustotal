package popular_threat_categories

import (
	"context"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// PopularThreatCategoriesServiceInterface defines the interface for popular threat categories operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/popular-threat-categories
	PopularThreatCategoriesServiceInterface interface {
		// GetPopularThreatCategories retrieves a list of popular threat categories
		//
		// Returns a list of malware categories commonly used in AV verdicts (e.g., trojan, dropper, ransomware).
		// These categories are normalized and used to classify threats across different antivirus engines.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/popular-threat-categories
		GetPopularThreatCategories(ctx context.Context) (*PopularThreatCategoriesResponse, *interfaces.Response, error)
	}

	// Service handles communication with the popular threat categories
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/popular-threat-categories
	Service struct {
		client interfaces.HTTPClient
	}
)

// Ensure Service implements PopularThreatCategoriesServiceInterface
var _ PopularThreatCategoriesServiceInterface = (*Service)(nil)

// NewService creates a new popular threat categories service
func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// GetPopularThreatCategories retrieves a list of popular threat categories
// URL: GET https://www.virustotal.com/api/v3/popular_threat_categories
// https://docs.virustotal.com/reference/popular-threat-categories
func (s *Service) GetPopularThreatCategories(ctx context.Context) (*PopularThreatCategoriesResponse, *interfaces.Response, error) {
	endpoint := EndpointPopularThreatCategories

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result PopularThreatCategoriesResponse
	resp, err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
