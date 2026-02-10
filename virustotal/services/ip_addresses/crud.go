package ipaddresses

import (
	"context"
	"encoding/json"
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

		// RescanIPAddress requests a rescan/reanalysis of an IP address
		//
		// IPs in VirusTotal can be reanalysed to refresh their verdicts, whois information, SSL certs, etc.
		// This endpoint sends the IP to be (re)scanned and returns an analysis ID that can be used to retrieve
		// the verdicts from the available vendors using the Analyses endpoint.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/rescan-ip
		RescanIPAddress(ctx context.Context, ip string) (*RescanIPAddressResponse, error)

		// AddCommentToIPAddress adds a comment to an IP address
		//
		// Posts a comment for an IP address. Words starting with # in the comment text are automatically
		// converted to tags. Returns the created comment object with its assigned ID, creation date, and extracted tags.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/ip-comments-post
		AddCommentToIPAddress(ctx context.Context, ip string, commentText string) (*AddCommentResponse, error)

		// GetObjectsRelatedToIPAddress retrieves objects related to an IP address
		//
		// Returns objects related to an IP address based on the specified relationship type.
		// Supported relationships include: comments, resolutions, communicating_files, referrer_files,
		// historical_ssl_certificates, historical_whois, and more. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/ip-relationships
		GetObjectsRelatedToIPAddress(ctx context.Context, ip string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error)

		// GetObjectDescriptorsRelatedToIPAddress retrieves object descriptors (IDs only) related to an IP address
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		// Supported relationships are the same as GetObjectsRelatedToIPAddress.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/ip-relationships-ids
		GetObjectDescriptorsRelatedToIPAddress(ctx context.Context, ip string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, error)

		// GetVotesOnIPAddress retrieves votes on an IP address
		//
		// Returns a list of votes from the VirusTotal community on whether the IP address is harmless or malicious.
		// Each vote includes the verdict, date, and value. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/ip-votes
		GetVotesOnIPAddress(ctx context.Context, ip string, opts *GetVotesOptions) (*VotesResponse, error)

		// AddVoteToIPAddress adds a vote to an IP address
		//
		// Posts a vote for an IP address. The verdict must be either "harmless" or "malicious".
		// Returns the created vote object with its assigned ID, creation date, and value.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/ip-votes-post
		AddVoteToIPAddress(ctx context.Context, ip string, verdict string) (*AddVoteResponse, error)
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
// Query Params: relationships (optional)
// https://docs.virustotal.com/reference/ip-info
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

// RescanIPAddress requests a rescan/reanalysis of an IP address
// URL: POST https://www.virustotal.com/api/v3/ip_addresses/{ip}/analyse
// https://docs.virustotal.com/reference/rescan-ip
func (s *Service) RescanIPAddress(ctx context.Context, ip string) (*RescanIPAddressResponse, error) {
	if ip == "" {
		return nil, fmt.Errorf("ip address is required")
	}

	endpoint := fmt.Sprintf("%s/%s/analyse", EndpointIPAddresses, ip)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result RescanIPAddressResponse
	err := s.client.Post(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// AddCommentToIPAddress adds a comment to an IP address
// URL: POST https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments
// https://docs.virustotal.com/reference/ip-comments-post
func (s *Service) AddCommentToIPAddress(ctx context.Context, ip string, commentText string) (*AddCommentResponse, error) {
	if ip == "" {
		return nil, fmt.Errorf("ip address is required")
	}
	if commentText == "" {
		return nil, fmt.Errorf("comment text is required")
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

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result AddCommentResponse
	err := s.client.Post(ctx, endpoint, requestBody, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetObjectsRelatedToIPAddress retrieves objects related to an IP address
// URL: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/ip-relationships
func (s *Service) GetObjectsRelatedToIPAddress(ctx context.Context, ip string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error) {
	if ip == "" {
		return nil, fmt.Errorf("ip address is required")
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint := fmt.Sprintf("%s/%s/%s", EndpointIPAddresses, ip, relationship)

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
		err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, err
		}

		return &result, nil
	}

	var allObjects []RelatedObject

	err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
		var pageResponse RelatedObjectsResponse
		if err := json.Unmarshal(pageData, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		allObjects = append(allObjects, pageResponse.Data...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &RelatedObjectsResponse{
		Data: allObjects,
	}, nil
}

// GetObjectDescriptorsRelatedToIPAddress retrieves object descriptors (IDs only) related to an IP address
// URL: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/ip-relationships-ids
func (s *Service) GetObjectDescriptorsRelatedToIPAddress(ctx context.Context, ip string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, error) {
	if ip == "" {
		return nil, fmt.Errorf("ip address is required")
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint := fmt.Sprintf("%s/%s/relationships/%s", EndpointIPAddresses, ip, relationship)

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
		err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, err
		}

		return &result, nil
	}

	var allDescriptors []ObjectDescriptor

	err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
		var pageResponse RelatedObjectDescriptorsResponse
		if err := json.Unmarshal(pageData, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		allDescriptors = append(allDescriptors, pageResponse.Data...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &RelatedObjectDescriptorsResponse{
		Data: allDescriptors,
	}, nil
}

// GetVotesOnIPAddress retrieves votes on an IP address
// URL: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/ip-votes
func (s *Service) GetVotesOnIPAddress(ctx context.Context, ip string, opts *GetVotesOptions) (*VotesResponse, error) {
	if ip == "" {
		return nil, fmt.Errorf("ip address is required")
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointIPAddresses, ip)

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
		err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, err
		}

		return &result, nil
	}

	var allVotes []Vote

	err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
		var pageResponse VotesResponse
		if err := json.Unmarshal(pageData, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		allVotes = append(allVotes, pageResponse.Data...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &VotesResponse{
		Data: allVotes,
	}, nil
}

// AddVoteToIPAddress adds a vote to an IP address
// URL: POST https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes
// https://docs.virustotal.com/reference/ip-votes-post
func (s *Service) AddVoteToIPAddress(ctx context.Context, ip string, verdict string) (*AddVoteResponse, error) {
	if ip == "" {
		return nil, fmt.Errorf("ip address is required")
	}
	if verdict == "" {
		return nil, fmt.Errorf("verdict is required")
	}
	if verdict != "harmless" && verdict != "malicious" {
		return nil, fmt.Errorf("verdict must be either 'harmless' or 'malicious'")
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

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result AddVoteResponse
	err := s.client.Post(ctx, endpoint, requestBody, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
