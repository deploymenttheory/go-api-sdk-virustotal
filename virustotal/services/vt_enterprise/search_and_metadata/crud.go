package search_and_metadata

import (
	"context"
	"fmt"
	"net/url"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// SearchAndMetadataServiceInterface defines the interface for Search & Metadata operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/search
	SearchAndMetadataServiceInterface interface {
		// Search performs a basic search for files, URLs, domains, IPs, and comments
		//
		// Returns objects matching the query. Query can be:
		// - A file hash (returns File object)
		// - A URL (returns URL object)
		// - A domain (returns Domain object)
		// - An IP address (returns IP address object)
		// - Comments by tags (returns list of Comment objects)
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/api-search
		Search(ctx context.Context, query string, opts *SearchOptions) (*SearchResponse, *interfaces.Response, error)

		// IntelligenceSearch performs advanced corpus search with VT Intelligence
		//
		// Searches for files in VirusTotal's dataset using the same query syntax as the
		// VirusTotal Intelligence UI. Supports advanced modifiers for filtering by file type,
		// size, detection count, and more. Set DescriptorsOnly to true for reduced latency
		// when only SHA-256 hashes are needed.
		//
		// Note: Requires VT Enterprise/Premium privileges. Consumes VirusTotal API quota
		// (private/premium API) or VirusTotal Intelligence quota.
		//
		// Note: Searches using fuzzy hashes (ssdeep, TLSH) are throttled to ~15 searches/minute.
		// Content searches cannot be sorted (order parameter has no effect).
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/intelligence-search
		IntelligenceSearch(ctx context.Context, query string, opts *IntelligenceSearchOptions) (*IntelligenceSearchResponse, *interfaces.Response, error)

		// GetSearchSnippets retrieves file content snippets for a search match
		//
		// Returns file content snippets that matched a query from the /intelligence/search endpoint.
		// Response is a list of strings containing hexdump and plain text. Matched content appears
		// between '*' characters with additional context.
		//
		// Note: Requires VT Enterprise/Premium privileges.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/intelligence-search-snippets
		GetSearchSnippets(ctx context.Context, snippetID string) (*SnippetsResponse, *interfaces.Response, error)

		// GetMetadata retrieves VirusTotal metadata
		//
		// Returns metadata including:
		// - Full list of antivirus engines in use
		// - List of existing privileges
		// - Available relationships for each object type
		//
		// Note: Requires VT Enterprise/Premium privileges.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/metadata
		GetMetadata(ctx context.Context) (*MetadataResponse, *interfaces.Response, error)
	}

	// Service handles communication with the Search & Metadata
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/search
	Service struct {
		client interfaces.HTTPClient
	}
)

var _ SearchAndMetadataServiceInterface = (*Service)(nil)

func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// =============================================================================
// Basic Search Operations
// =============================================================================

// Search performs a basic search for files, URLs, domains, IPs, and comments
// URL: GET https://www.virustotal.com/api/v3/search
// Query Params: query (required), limit (optional), cursor (optional)
// https://docs.virustotal.com/reference/api-search
func (s *Service) Search(ctx context.Context, query string, opts *SearchOptions) (*SearchResponse, *interfaces.Response, error) {
	if err := ValidateSearchQuery(query); err != nil {
		return nil, nil, err
	}

	endpoint := EndpointSearch

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := map[string]string{
		"query": query,
	}

	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}
	}

	var result SearchResponse
	resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
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
func (s *Service) IntelligenceSearch(ctx context.Context, query string, opts *IntelligenceSearchOptions) (*IntelligenceSearchResponse, *interfaces.Response, error) {
	if err := ValidateSearchQuery(query); err != nil {
		return nil, nil, err
	}

	endpoint := EndpointIntelligenceSearch

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := map[string]string{
		"query": url.QueryEscape(query),
	}

	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}
		if opts.Order != "" {
			queryParams["order"] = opts.Order
		}
		if opts.DescriptorsOnly {
			queryParams["descriptors_only"] = "true"
		}
	}

	var result IntelligenceSearchResponse
	resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
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
func (s *Service) GetSearchSnippets(ctx context.Context, snippetID string) (*SnippetsResponse, *interfaces.Response, error) {
	if err := ValidateSnippetID(snippetID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSearchSnippets, snippetID)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result SnippetsResponse
	resp, err := s.client.Get(ctx, endpoint, nil, headers, &result)
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
func (s *Service) GetMetadata(ctx context.Context) (*MetadataResponse, *interfaces.Response, error) {
	endpoint := EndpointMetadata

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result MetadataResponse
	resp, err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
