package ipaddresses

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the IP addresses
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference
type Service struct {
	client client.Client
}

// NewService creates a new IP addresses service
func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// GetIPAddressReport retrieves information about an IP address
// URL: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
// Query Params: relationships (optional)
// https://docs.virustotal.com/reference/ip-info
func (s *Service) GetIPAddressReport(ctx context.Context, ip string, opts *RequestQueryOptions) (*IPAddressResponse, *resty.Response, error) {
	if ip == "" {
		return nil, nil, fmt.Errorf("ip address is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointIPAddresses, ip)

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON)

	if opts != nil && opts.Relationships != "" {
		builder = builder.SetQueryParam("relationships", opts.Relationships)
	}

	var result IPAddressResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// RescanIPAddress requests a rescan/reanalysis of an IP address
// URL: POST https://www.virustotal.com/api/v3/ip_addresses/{ip}/analyse
// https://docs.virustotal.com/reference/rescan-ip
func (s *Service) RescanIPAddress(ctx context.Context, ip string) (*RescanIPAddressResponse, *resty.Response, error) {
	if ip == "" {
		return nil, nil, fmt.Errorf("ip address is required")
	}

	endpoint := fmt.Sprintf("%s/%s/analyse", EndpointIPAddresses, ip)

	var result RescanIPAddressResponse
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

// AddCommentToIPAddress adds a comment to an IP address
// URL: POST https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments
// https://docs.virustotal.com/reference/ip-comments-post
func (s *Service) AddCommentToIPAddress(ctx context.Context, ip string, commentText string) (*AddCommentResponse, *resty.Response, error) {
	if ip == "" {
		return nil, nil, fmt.Errorf("ip address is required")
	}
	if commentText == "" {
		return nil, nil, fmt.Errorf("comment text is required")
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointIPAddresses, ip)

	requestBody := AddCommentRequest{
		Data: CommentData{
			Type: "comment",
			Attributes: CommentAttributes{
				Text: commentText,
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

// GetObjectsRelatedToIPAddress retrieves objects related to an IP address
// URL: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/ip-relationships
func (s *Service) GetObjectsRelatedToIPAddress(ctx context.Context, ip string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if ip == "" {
		return nil, nil, fmt.Errorf("ip address is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointIPAddresses, ip, relationship, false)
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

// GetObjectDescriptorsRelatedToIPAddress retrieves object descriptors (IDs only) related to an IP address
// URL: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/ip-relationships-ids
func (s *Service) GetObjectDescriptorsRelatedToIPAddress(ctx context.Context, ip string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *resty.Response, error) {
	if ip == "" {
		return nil, nil, fmt.Errorf("ip address is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointIPAddresses, ip, relationship, true)
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

// GetVotesOnIPAddress retrieves votes on an IP address
// URL: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/ip-votes
func (s *Service) GetVotesOnIPAddress(ctx context.Context, ip string, opts *GetVotesOptions) (*VotesResponse, *resty.Response, error) {
	if ip == "" {
		return nil, nil, fmt.Errorf("ip address is required")
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointIPAddresses, ip)

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

// AddVoteToIPAddress adds a vote to an IP address
// URL: POST https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes
// https://docs.virustotal.com/reference/ip-votes-post
func (s *Service) AddVoteToIPAddress(ctx context.Context, ip string, verdict string) (*AddVoteResponse, *resty.Response, error) {
	if ip == "" {
		return nil, nil, fmt.Errorf("ip address is required")
	}
	if verdict == "" {
		return nil, nil, fmt.Errorf("verdict is required")
	}
	if verdict != "harmless" && verdict != "malicious" {
		return nil, nil, fmt.Errorf("verdict must be either 'harmless' or 'malicious'")
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointIPAddresses, ip)

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
