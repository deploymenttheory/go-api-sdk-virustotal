package search_and_metadata

import (
	"context"
	"fmt"
	"net/url"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the Search & Metadata
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference/search
type Service struct {
	client client.Client
}

func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// =============================================================================
// Basic Search Operations
// =============================================================================

// Search performs a basic search for files, URLs, domains, IPs, and comments
// URL: GET https://www.virustotal.com/api/v3/search
// Query Params: query (required), limit (optional), cursor (optional)
// https://docs.virustotal.com/reference/api-search
func (s *Service) Search(ctx context.Context, query string, opts *SearchOptions) (*SearchResponse, *resty.Response, error) {
	if err := ValidateSearchQuery(query); err != nil {
		return nil, nil, err
	}

	endpoint := EndpointSearch

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetQueryParam("query", query)

	if opts != nil {
		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}
	}

	var result SearchResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// Intelligence Search Operations (VT Enterprise)
// =============================================================================

// IntelligenceSearch performs advanced corpus search with VT Intelligence
// URL: GET https://www.virustotal.com/api/v3/intelligence/search
// Query Params: query (required), limit (optional), cursor (optional), order (optional), descriptors_only (optional)
// Note: Requires VT Enterprise/Premium privileges. Fuzzy hash searches throttled to ~15/min.
// https://docs.virustotal.com/reference/intelligence-search
func (s *Service) IntelligenceSearch(ctx context.Context, query string, opts *IntelligenceSearchOptions) (*IntelligenceSearchResponse, *resty.Response, error) {
	if err := ValidateSearchQuery(query); err != nil {
		return nil, nil, err
	}

	endpoint := EndpointIntelligenceSearch

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetQueryParam("query", url.QueryEscape(query))

	if opts != nil {
		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}
		if opts.Order != "" {
			builder = builder.SetQueryParam("order", opts.Order)
		}
		if opts.DescriptorsOnly {
			builder = builder.SetQueryParam("descriptors_only", "true")
		}
	}

	var result IntelligenceSearchResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// Search Snippets Operations (VT Enterprise)
// =============================================================================

// GetSearchSnippets retrieves file content snippets for a search match
// URL: GET https://www.virustotal.com/api/v3/intelligence/search/snippets/{snippet}
// Note: Requires VT Enterprise/Premium privileges.
// https://docs.virustotal.com/reference/intelligence-search-snippets
func (s *Service) GetSearchSnippets(ctx context.Context, snippetID string) (*SnippetsResponse, *resty.Response, error) {
	if err := ValidateSnippetID(snippetID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSearchSnippets, snippetID)

	var result SnippetsResponse
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

// =============================================================================
// Metadata Operations (VT Enterprise)
// =============================================================================

// GetMetadata retrieves VirusTotal metadata
// URL: GET https://www.virustotal.com/api/v3/metadata
// Note: Requires VT Enterprise/Premium privileges.
// https://docs.virustotal.com/reference/metadata
func (s *Service) GetMetadata(ctx context.Context) (*MetadataResponse, *resty.Response, error) {
	endpoint := EndpointMetadata

	var result MetadataResponse
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
