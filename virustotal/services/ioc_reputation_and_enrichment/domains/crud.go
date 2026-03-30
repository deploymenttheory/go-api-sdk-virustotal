package domains

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the domains
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference
type Service struct {
	client client.Client
}

// NewService creates a new domains service
func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// GetDomainReport retrieves information about a domain
// URL: GET https://www.virustotal.com/api/v3/domains/{domain}
// https://docs.virustotal.com/reference/domain-info
func (s *Service) GetDomainReport(ctx context.Context, domain string) (*DomainResponse, *resty.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointDomains, domain)

	var result DomainResponse
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

// RescanDomain requests a new analysis for a domain
// URL: POST https://www.virustotal.com/api/v3/domains/{domain}/analyse
// https://docs.virustotal.com/reference/domains-rescan
func (s *Service) RescanDomain(ctx context.Context, domain string) (*RescanResponse, *resty.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}

	endpoint := fmt.Sprintf("%s/%s/analyse", EndpointDomains, domain)

	var result RescanResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetResult(&result).
		Post(endpoint)
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
func (s *Service) GetCommentsOnDomain(ctx context.Context, domain string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointDomains, domain)

	if opts != nil {
		builder := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON)

		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}

		var result RelatedObjectsResponse
		resp, err := builder.SetResult(&result).Get(endpoint)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allObjects []RelatedObject

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		GetPaginated(endpoint, func(pageData []byte) error {
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
func (s *Service) AddCommentToDomain(ctx context.Context, domain string, comment string) (*AddCommentResponse, *resty.Response, error) {
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

	var result AddCommentResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(requestBody).
		SetResult(&result).
		Post(endpoint)
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
func (s *Service) GetObjectsRelatedToDomain(ctx context.Context, domain string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
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

	if opts != nil {
		builder := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON)

		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}

		var result RelatedObjectsResponse
		resp, err := builder.SetResult(&result).Get(endpoint)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allObjects []RelatedObject

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		GetPaginated(endpoint, func(pageData []byte) error {
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
func (s *Service) GetObjectDescriptorsRelatedToDomain(ctx context.Context, domain string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *resty.Response, error) {
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

	if opts != nil {
		builder := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON)

		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}

		var result RelatedObjectDescriptorsResponse
		resp, err := builder.SetResult(&result).Get(endpoint)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allDescriptors []ObjectDescriptor

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		GetPaginated(endpoint, func(pageData []byte) error {
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
func (s *Service) GetDNSResolutionObject(ctx context.Context, id string) (*ResolutionResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("resolution ID is required")
	}

	endpoint := fmt.Sprintf("/v3/resolutions/%s", id)

	var result ResolutionResponse
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

// GetVotesOnDomain retrieves community votes on a domain
// URL: GET https://www.virustotal.com/api/v3/domains/{domain}/votes
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/domains-votes-get
func (s *Service) GetVotesOnDomain(ctx context.Context, domain string, opts *GetVotesOptions) (*VotesResponse, *resty.Response, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain is required")
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointDomains, domain)

	if opts != nil {
		builder := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON)

		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}

		var result VotesResponse
		resp, err := builder.SetResult(&result).Get(endpoint)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allVotes []Vote

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		GetPaginated(endpoint, func(pageData []byte) error {
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
func (s *Service) AddVoteToDomain(ctx context.Context, domain string, verdict string) (*AddVoteResponse, *resty.Response, error) {
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

	var result AddVoteResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(requestBody).
		SetResult(&result).
		Post(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
