package domains

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// DomainsServiceInterface defines the interface for domain operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	DomainsServiceInterface interface {
		// GetDomainReport retrieves information about a domain
		//
		// Returns domain reputation data including categories, DNS records, WHOIS information, SSL certificates,
		// malware detection stats, popularity ranks, and community votes. Optionally include relationships.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/domain-info
		GetDomainReport(ctx context.Context, domain string) (*DomainResponse, *interfaces.Response, error)

		// RescanDomain requests a rescan/reanalysis of a domain
		//
		// Domains in VirusTotal can be reanalysed to refresh their verdicts, whois information, SSL certs, etc.
		// This endpoint sends the domain to be (re)scanned and returns an analysis ID that can be used to retrieve
		// the verdicts from the available vendors using the Analyses endpoint.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/domains-rescan
		RescanDomain(ctx context.Context, domain string) (*RescanResponse, *interfaces.Response, error)

		// GetCommentsOnDomain retrieves comments on a domain
		//
		// Returns a list of comments posted by the VirusTotal community about the domain.
		// Comments may include tags extracted from words starting with #. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/domains-comments-get
		GetCommentsOnDomain(ctx context.Context, domain string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error)

		// AddCommentToDomain adds a comment to a domain
		//
		// Posts a comment for a domain. Words starting with # in the comment text are automatically
		// converted to tags. Returns the created comment object with its assigned ID, creation date, and extracted tags.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/domains-comments-post
		AddCommentToDomain(ctx context.Context, domain string, comment string) (*AddCommentResponse, *interfaces.Response, error)

		// GetObjectsRelatedToDomain retrieves objects related to a domain
		//
		// Returns objects related to a domain based on the specified relationship type.
		// Supported relationships include: communicating_files, downloaded_files, historical_ssl_certificates,
		// historical_whois, subdomains, resolutions, and more. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/domains-relationships
		GetObjectsRelatedToDomain(ctx context.Context, domain string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error)

		// GetObjectDescriptorsRelatedToDomain retrieves object descriptors (IDs only) related to a domain
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		// Supported relationships are the same as GetObjectsRelatedToDomain.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/domains-relationships-ids
		GetObjectDescriptorsRelatedToDomain(ctx context.Context, domain string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *interfaces.Response, error)

		// GetDNSResolutionObject retrieves a DNS resolution object by its ID
		//
		// Returns a resolution object showing the relationship between a domain and IP address.
		// The resolution ID is formed by combining the IP address and domain (e.g., "93.184.216.34-example.com").
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-resolution-by-id
		GetDNSResolutionObject(ctx context.Context, id string) (*ResolutionResponse, *interfaces.Response, error)

		// GetVotesOnDomain retrieves votes on a domain
		//
		// Returns a list of votes from the VirusTotal community on whether the domain is harmless or malicious.
		// Each vote includes the verdict, date, and value. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/domains-votes-get
		GetVotesOnDomain(ctx context.Context, domain string, opts *GetVotesOptions) (*VotesResponse, *interfaces.Response, error)

		// AddVoteToDomain adds a vote to a domain
		//
		// Posts a vote for a domain. The verdict must be either "harmless" or "malicious".
		// Returns the created vote object with its assigned ID, creation date, and value.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/domain-votes-post
		AddVoteToDomain(ctx context.Context, domain string, verdict string) (*AddVoteResponse, *interfaces.Response, error)
	}

	// Service handles communication with the domains
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	Service struct {
		client interfaces.HTTPClient
	}
)

// Ensure Service implements DomainsServiceInterface
var _ DomainsServiceInterface = (*Service)(nil)

// NewService creates a new domains service
func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// GetDomainReport retrieves information about a domain
// URL: GET https://www.virustotal.com/api/v3/domains/{domain}
// https://docs.virustotal.com/reference/domain-info
func (s *Service) GetDomainReport(ctx context.Context, domain string) (*DomainResponse, *interfaces.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointDomains, domain)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result DomainResponse
	resp, err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// RescanDomain requests a new analysis for a domain
// URL: POST https://www.virustotal.com/api/v3/domains/{domain}/analyse
// https://docs.virustotal.com/reference/domains-rescan
func (s *Service) RescanDomain(ctx context.Context, domain string) (*RescanResponse, *interfaces.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}

	endpoint := fmt.Sprintf("%s/%s/analyse", EndpointDomains, domain)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result RescanResponse
	resp, err := s.client.Post(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetCommentsOnDomain retrieves comments on a domain
// URL: GET https://www.virustotal.com/api/v3/domains/{domain}/comments
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/domains-comments-get
func (s *Service) GetCommentsOnDomain(ctx context.Context, domain string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointDomains, domain)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}

		var result RelatedObjectsResponse
		resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allObjects []RelatedObject

	resp, err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
		var pageResponse RelatedObjectsResponse
		if err := json.Unmarshal(pageData, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		allObjects = append(allObjects, pageResponse.Data...)
		return nil
	})

	if err != nil {
		return nil, resp, err
	}

	return &RelatedObjectsResponse{
		Data: allObjects,
	}, resp, nil
}

// AddCommentToDomain adds a comment to a domain
// URL: POST https://www.virustotal.com/api/v3/domains/{domain}/comments
// https://docs.virustotal.com/reference/domains-comments-post
func (s *Service) AddCommentToDomain(ctx context.Context, domain string, comment string) (*AddCommentResponse, *interfaces.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}
	if comment == "" {
		return nil, nil, fmt.Errorf("comment text is required")
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointDomains, domain)

	requestBody := AddCommentRequest{
		Data: CommentData{
			Type: "comment",
			Attributes: CommentAttributes{
				Text: comment,
			},
		},
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result AddCommentResponse
	resp, err := s.client.Post(ctx, endpoint, requestBody, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetObjectsRelatedToDomain retrieves objects related to a domain through a specified relationship
// URL: GET https://www.virustotal.com/api/v3/domains/{domain}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/domains-relationships
func (s *Service) GetObjectsRelatedToDomain(ctx context.Context, domain string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointDomains, domain, relationship, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}

		var result RelatedObjectsResponse
		resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allObjects []RelatedObject

	resp, err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
		var pageResponse RelatedObjectsResponse
		if err := json.Unmarshal(pageData, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		allObjects = append(allObjects, pageResponse.Data...)
		return nil
	})

	if err != nil {
		return nil, resp, err
	}

	return &RelatedObjectsResponse{
		Data: allObjects,
	}, resp, nil
}

// GetObjectDescriptorsRelatedToDomain retrieves lightweight object descriptors related to a domain
// URL: GET https://www.virustotal.com/api/v3/domains/{domain}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/domains-relationships-ids
func (s *Service) GetObjectDescriptorsRelatedToDomain(ctx context.Context, domain string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *interfaces.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointDomains, domain, relationship, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}

		var result RelatedObjectDescriptorsResponse
		resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allDescriptors []ObjectDescriptor

	resp, err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
		var pageResponse RelatedObjectDescriptorsResponse
		if err := json.Unmarshal(pageData, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		allDescriptors = append(allDescriptors, pageResponse.Data...)
		return nil
	})

	if err != nil {
		return nil, resp, err
	}

	return &RelatedObjectDescriptorsResponse{
		Data: allDescriptors,
	}, resp, nil
}

// GetDNSResolutionObject retrieves a DNS resolution object by its ID
// URL: GET https://www.virustotal.com/api/v3/resolutions/{id}
// https://docs.virustotal.com/reference/get-resolution-by-id
func (s *Service) GetDNSResolutionObject(ctx context.Context, id string) (*ResolutionResponse, *interfaces.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("resolution ID is required")
	}

	endpoint := fmt.Sprintf("/resolutions/%s", id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result ResolutionResponse
	resp, err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetVotesOnDomain retrieves community votes on a domain
// URL: GET https://www.virustotal.com/api/v3/domains/{domain}/votes
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/domains-votes-get
func (s *Service) GetVotesOnDomain(ctx context.Context, domain string, opts *GetVotesOptions) (*VotesResponse, *interfaces.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointDomains, domain)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}

		var result VotesResponse
		resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allVotes []Vote

	resp, err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
		var pageResponse VotesResponse
		if err := json.Unmarshal(pageData, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		allVotes = append(allVotes, pageResponse.Data...)
		return nil
	})

	if err != nil {
		return nil, resp, err
	}

	return &VotesResponse{
		Data: allVotes,
	}, resp, nil
}

// AddVoteToDomain adds a vote (harmless or malicious) to a domain
// URL: POST https://www.virustotal.com/api/v3/domains/{domain}/votes
// https://docs.virustotal.com/reference/domain-votes-post
func (s *Service) AddVoteToDomain(ctx context.Context, domain string, verdict string) (*AddVoteResponse, *interfaces.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}
	if verdict == "" {
		return nil, nil, fmt.Errorf("verdict is required")
	}
	if verdict != "harmless" && verdict != "malicious" {
		return nil, nil, fmt.Errorf("verdict must be 'harmless' or 'malicious', got: %s", verdict)
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointDomains, domain)

	requestBody := AddVoteRequest{
		Data: VoteData{
			Type: "vote",
			Attributes: VoteDataAttributes{
				Verdict: verdict,
			},
		},
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result AddVoteResponse
	resp, err := s.client.Post(ctx, endpoint, requestBody, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
