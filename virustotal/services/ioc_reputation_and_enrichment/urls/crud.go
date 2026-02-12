package urls

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// URLsServiceInterface defines the interface for URL operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	URLsServiceInterface interface {
		// ScanURL submits a URL for scanning
		//
		// Returns an analysis ID that can be used to retrieve the scan results from the Analyses endpoint.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/scan-url
		ScanURL(ctx context.Context, url string) (*ScanURLResponse, error)

		// GetURLReport retrieves information about a URL
		//
		// Returns URL reputation data including detection results from security engines, HTTP response details,
		// categories, community votes, and relationships. The URL ID can be either the SHA-256 hash of the
		// canonized URL or the base64-encoded URL (without padding).
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/url-info
		GetURLReport(ctx context.Context, urlID string) (*URLResponse, error)

		// RescanURL requests a rescan/reanalysis of a URL
		//
		// URLs in VirusTotal can be reanalysed to refresh their verdicts. This endpoint sends the URL
		// to be (re)scanned and returns an analysis ID that can be used to retrieve the verdicts from
		// the available vendors using the Analyses endpoint.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/urls-analyse
		RescanURL(ctx context.Context, urlID string) (*RescanURLResponse, error)

		// GetCommentsOnURL retrieves comments on a URL
		//
		// Returns a list of comments posted by the VirusTotal community about the URL.
		// Comments may include tags extracted from words starting with #. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/urls-comments-get
		GetCommentsOnURL(ctx context.Context, urlID string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error)

		// AddCommentToURL adds a comment to a URL
		//
		// Posts a comment for a URL. Words starting with # in the comment text are automatically
		// converted to tags. Returns the created comment object with its assigned ID, creation date, and extracted tags.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/urls-comments-post
		AddCommentToURL(ctx context.Context, urlID string, comment string) (*AddCommentResponse, error)

		// GetObjectsRelatedToURL retrieves objects related to a URL
		//
		// Returns objects related to a URL based on the specified relationship type.
		// Supported relationships include: analyses, collections, comments, communicating_files, contacted_domains,
		// contacted_ips, downloaded_files, graphs, and more. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/urls-relationships
		GetObjectsRelatedToURL(ctx context.Context, urlID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error)

		// GetObjectDescriptorsRelatedToURL retrieves object descriptors (IDs only) related to a URL
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		// Supported relationships are the same as GetObjectsRelatedToURL.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/urls-relationships-ids
		GetObjectDescriptorsRelatedToURL(ctx context.Context, urlID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, error)

		// GetVotesOnURL retrieves votes on a URL
		//
		// Returns a list of votes from the VirusTotal community on whether the URL is harmless or malicious.
		// Each vote includes the verdict, date, and value. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/urls-votes-get
		GetVotesOnURL(ctx context.Context, urlID string, opts *GetVotesOptions) (*VotesResponse, error)

		// AddVoteToURL adds a vote to a URL
		//
		// Posts a vote for a URL. The verdict must be either "harmless" or "malicious".
		// Returns the created vote object with its assigned ID, creation date, and value.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/urls-votes-post
		AddVoteToURL(ctx context.Context, urlID string, verdict string) (*AddVoteResponse, error)
	}

	// Service handles communication with the URLs
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	Service struct {
		client interfaces.HTTPClient
	}
)

var _ URLsServiceInterface = (*Service)(nil)

func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// =============================================================================
// URL Scanning Operations
// =============================================================================

// ScanURL submits a URL for scanning
// URL: POST https://www.virustotal.com/api/v3/urls
// https://docs.virustotal.com/reference/scan-url
func (s *Service) ScanURL(ctx context.Context, url string) (*ScanURLResponse, error) {
	if url == "" {
		return nil, fmt.Errorf("URL is required")
	}

	endpoint := EndpointURLs

	formData := map[string]string{
		"url": url,
	}

	headers := map[string]string{
		"Accept": "application/json",
	}

	var result ScanURLResponse
	err := s.client.PostForm(ctx, endpoint, formData, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// URL Report Operations
// =============================================================================

// GetURLReport retrieves information about a URL
// URL: GET https://www.virustotal.com/api/v3/urls/{id}
// https://docs.virustotal.com/reference/url-info
func (s *Service) GetURLReport(ctx context.Context, urlID string) (*URLResponse, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointURLs, urlID)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result URLResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// URL Rescan Operations
// =============================================================================

// RescanURL requests a new analysis for a URL
// URL: POST https://www.virustotal.com/api/v3/urls/{id}/analyse
// https://docs.virustotal.com/reference/urls-analyse
func (s *Service) RescanURL(ctx context.Context, urlID string) (*RescanURLResponse, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/analyse", EndpointURLs, urlID)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result RescanURLResponse
	err := s.client.Post(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// Comment Operations
// =============================================================================

// GetCommentsOnURL retrieves comments on a URL
// URL: GET https://www.virustotal.com/api/v3/urls/{id}/comments
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/urls-comments-get
func (s *Service) GetCommentsOnURL(ctx context.Context, urlID string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointURLs, urlID)

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

// AddCommentToURL adds a comment to a URL
// URL: POST https://www.virustotal.com/api/v3/urls/{id}/comments
// https://docs.virustotal.com/reference/urls-comments-post
func (s *Service) AddCommentToURL(ctx context.Context, urlID string, comment string) (*AddCommentResponse, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, err
	}
	if comment == "" {
		return nil, fmt.Errorf("comment text is required")
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

// =============================================================================
// Related Objects Operations
// =============================================================================

// GetObjectsRelatedToURL retrieves objects related to a URL through a specified relationship
// URL: GET https://www.virustotal.com/api/v3/urls/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/urls-relationships
func (s *Service) GetObjectsRelatedToURL(ctx context.Context, urlID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, err
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointURLs, urlID, relationship, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
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
		err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, err
		}

		return &result, nil
	}

	var allObjects []RelatedObject

	err = s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
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

// GetObjectDescriptorsRelatedToURL retrieves lightweight object descriptors related to a URL
// URL: GET https://www.virustotal.com/api/v3/urls/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/urls-relationships-ids
func (s *Service) GetObjectDescriptorsRelatedToURL(ctx context.Context, urlID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, err
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointURLs, urlID, relationship, true)
	if err != nil {
		return nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
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

		var result ObjectDescriptorsResponse
		err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, err
		}

		return &result, nil
	}

	var allDescriptors []ObjectDescriptor

	err = s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
		var pageResponse ObjectDescriptorsResponse
		if err := json.Unmarshal(pageData, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		allDescriptors = append(allDescriptors, pageResponse.Data...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &ObjectDescriptorsResponse{
		Data: allDescriptors,
	}, nil
}

// =============================================================================
// Votes Operations
// =============================================================================

// GetVotesOnURL retrieves community votes on a URL
// URL: GET https://www.virustotal.com/api/v3/urls/{id}/votes
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/urls-votes-get
func (s *Service) GetVotesOnURL(ctx context.Context, urlID string, opts *GetVotesOptions) (*VotesResponse, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointURLs, urlID)

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

// AddVoteToURL adds a vote (harmless or malicious) to a URL
// URL: POST https://www.virustotal.com/api/v3/urls/{id}/votes
// https://docs.virustotal.com/reference/urls-votes-post
func (s *Service) AddVoteToURL(ctx context.Context, urlID string, verdict string) (*AddVoteResponse, error) {
	if err := ValidateURLID(urlID); err != nil {
		return nil, err
	}
	if verdict == "" {
		return nil, fmt.Errorf("verdict is required")
	}
	if verdict != "harmless" && verdict != "malicious" {
		return nil, fmt.Errorf("verdict must be 'harmless' or 'malicious', got: %s", verdict)
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
