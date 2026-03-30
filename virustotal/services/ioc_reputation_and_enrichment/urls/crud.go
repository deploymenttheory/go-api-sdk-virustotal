package urls

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the URLs
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference
type Service struct {
	client client.Client
}

func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// =============================================================================
// URL Scanning Operations
// =============================================================================

// ScanURL submits a URL for scanning
// URL: POST https://www.virustotal.com/api/v3/urls
// Note: Protected domains (e.g., virustotal.com) require Private Scanning license.
// https://docs.virustotal.com/reference/scan-url
func (s *Service) ScanURL(ctx context.Context, url string) (*ScanURLResponse, *resty.Response, error) {
	if url == "" {
		return nil, nil, fmt.Errorf("URL is required")
	}

	endpoint := EndpointURLs

	formData := map[string]string{
		"url": url,
	}

	var result ScanURLResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetFormData(formData).
		SetResult(&result).
		Post(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// URL Report Operations
// =============================================================================

// GetURLReport retrieves information about a URL
// URL: GET https://www.virustotal.com/api/v3/urls/{id}
// https://docs.virustotal.com/reference/url-info
func (s *Service) GetURLReport(ctx context.Context, urlID string) (*URLResponse, *resty.Response, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointURLs, urlID)

	var result URLResponse
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
// URL Rescan Operations
// =============================================================================

// RescanURL requests a new analysis for a URL
// URL: POST https://www.virustotal.com/api/v3/urls/{id}/analyse
// https://docs.virustotal.com/reference/urls-analyse
func (s *Service) RescanURL(ctx context.Context, urlID string) (*RescanURLResponse, *resty.Response, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/analyse", EndpointURLs, urlID)

	var result RescanURLResponse
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

// =============================================================================
// Comment Operations
// =============================================================================

// GetCommentsOnURL retrieves comments on a URL
// URL: GET https://www.virustotal.com/api/v3/urls/{id}/comments
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/urls-comments-get
func (s *Service) GetCommentsOnURL(ctx context.Context, urlID string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointURLs, urlID)

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

// AddCommentToURL adds a comment to a URL
// URL: POST https://www.virustotal.com/api/v3/urls/{id}/comments
// https://docs.virustotal.com/reference/urls-comments-post
func (s *Service) AddCommentToURL(ctx context.Context, urlID string, comment string) (*AddCommentResponse, *resty.Response, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, nil, err
	}
	if comment == "" {
		return nil, nil, fmt.Errorf("comment text is required")
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointURLs, urlID)

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

// =============================================================================
// Related Objects Operations
// =============================================================================

// GetObjectsRelatedToURL retrieves objects related to a URL through a specified relationship
// URL: GET https://www.virustotal.com/api/v3/urls/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// Note: Many relationships require VT Enterprise license (contacted_domains, contacted_ips, analyses, etc.).
// https://docs.virustotal.com/reference/urls-relationships
func (s *Service) GetObjectsRelatedToURL(ctx context.Context, urlID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, nil, err
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointURLs, urlID, relationship, false)
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

// GetObjectDescriptorsRelatedToURL retrieves lightweight object descriptors related to a URL
// URL: GET https://www.virustotal.com/api/v3/urls/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// Note: Many relationships require VT Enterprise license (contacted_domains, contacted_ips, analyses, etc.).
// https://docs.virustotal.com/reference/urls-relationships-ids
func (s *Service) GetObjectDescriptorsRelatedToURL(ctx context.Context, urlID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *resty.Response, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, nil, err
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointURLs, urlID, relationship, true)
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

		var result ObjectDescriptorsResponse
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
			var pageResponse ObjectDescriptorsResponse
			if err := json.Unmarshal(pageData, &pageResponse); err != nil {
				return fmt.Errorf("failed to unmarshal page: %w", err)
			}
			allDescriptors = append(allDescriptors, pageResponse.Data...)
			return nil
		})

	if err != nil {
		return nil, resp, err
	}

	return &ObjectDescriptorsResponse{
		Data: allDescriptors,
	}, resp, nil
}

// =============================================================================
// Votes Operations
// =============================================================================

// GetVotesOnURL retrieves community votes on a URL
// URL: GET https://www.virustotal.com/api/v3/urls/{id}/votes
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/urls-votes-get
func (s *Service) GetVotesOnURL(ctx context.Context, urlID string, opts *GetVotesOptions) (*VotesResponse, *resty.Response, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointURLs, urlID)

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

// AddVoteToURL adds a vote (harmless or malicious) to a URL
// URL: POST https://www.virustotal.com/api/v3/urls/{id}/votes
// https://docs.virustotal.com/reference/urls-votes-post
func (s *Service) AddVoteToURL(ctx context.Context, urlID string, verdict string) (*AddVoteResponse, *resty.Response, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, nil, err
	}
	if verdict == "" {
		return nil, nil, fmt.Errorf("verdict is required")
	}
	if verdict != "harmless" && verdict != "malicious" {
		return nil, nil, fmt.Errorf("verdict must be 'harmless' or 'malicious', got: %s", verdict)
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointURLs, urlID)

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
