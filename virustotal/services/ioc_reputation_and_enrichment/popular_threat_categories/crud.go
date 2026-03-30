package popular_threat_categories

import (
	"context"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the popular threat categories
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference/popular-threat-categories
type Service struct {
	client client.Client
}

// NewService creates a new popular threat categories service
func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// GetPopularThreatCategories retrieves a list of popular threat categories
// URL: GET https://www.virustotal.com/api/v3/popular_threat_categories
// https://docs.virustotal.com/reference/popular-threat-categories
func (s *Service) GetPopularThreatCategories(ctx context.Context) (*PopularThreatCategoriesResponse, *resty.Response, error) {
	endpoint := EndpointPopularThreatCategories

	var result PopularThreatCategoriesResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetResult(&result).
		Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
