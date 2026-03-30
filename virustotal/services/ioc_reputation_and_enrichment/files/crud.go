package files

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the files
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference
type Service struct {
	client client.Client
}

// NewService creates a new files service
func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// UploadFile uploads and analyses a file
// URL: POST https://www.virustotal.com/api/v3/files (for files <= 32MB)
//
//	POST [upload_url] (for files > 32MB and <= 650MB)
//
// Automatically handles file size detection and selects the appropriate upload endpoint.
// Files larger than 32MB require using the /files/upload_url endpoint first.
// Files larger than 650MB are not supported.
//
// The file content is streamed to avoid loading the entire file into memory.
// Progress updates are sent through the ProgressCallback channel if provided.
//
// https://docs.virustotal.com/reference/files-scan
// https://docs.virustotal.com/reference/files-upload-url
func (s *Service) UploadFile(ctx context.Context, request *UploadFileRequest) (*UploadFileResponse, *resty.Response, error) {
	if request == nil || request.File == nil {
		return nil, nil, fmt.Errorf("file is required")
	}
	if request.Filename == "" {
		return nil, nil, fmt.Errorf("filename is required")
	}

	reader, fileSize, err := prepareReader(request.File)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare file for upload: %w", err)
	}

	if err := validateFileSize(fileSize); err != nil {
		return nil, nil, err
	}

	// Update request with actual file size
	request.FileSize = fileSize
	request.File = reader

	// Determine upload endpoint based on file size
	var endpoint string

	if shouldUseLargeFileEndpoint(fileSize) {
		// For files larger than 32MB, get a special upload URL
		// This returns an absolute URL like: http://www.virustotal.com/_ah/upload/AMmfu6b...
		// The HTTP client will use this absolute URL directly (base URL is ignored)
		uploadURLResp, _, err := s.GetUploadURL(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get upload URL for large file: %w", err)
		}
		endpoint = uploadURLResp.Data // Absolute URL
	} else {
		// For files <= 32MB, use the standard endpoint (relative path)
		// This will be combined with the base URL by the HTTP client
		endpoint = EndpointFiles // Relative path: "/files"
	}

	var formFields map[string]string
	if request.Password != "" {
		formFields = map[string]string{
			"password": request.Password,
		}
	}

	var result UploadFileResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetMultipartFile("file", request.Filename, request.File, request.FileSize, client.MultipartProgressCallback(request.ProgressCallback)).
		SetMultipartFormData(formFields).
		SetResult(&result).
		Post(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetUploadURL gets a URL for uploading files larger than 32MB
// URL: GET https://www.virustotal.com/api/v3/files/upload_url
// https://docs.virustotal.com/reference/files-upload-url
func (s *Service) GetUploadURL(ctx context.Context) (*UploadURLResponse, *resty.Response, error) {
	endpoint := fmt.Sprintf("%s/upload_url", EndpointFiles)

	var result UploadURLResponse
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

// GetFileReport retrieves information about a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}
// https://docs.virustotal.com/reference/file-info
func (s *Service) GetFileReport(ctx context.Context, id string) (*FileResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointFiles, id)

	var result FileResponse
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

// RescanFile requests a file rescan (re-analysis)
// URL: POST https://www.virustotal.com/api/v3/files/{id}/analyse
// https://docs.virustotal.com/reference/files-analyse
func (s *Service) RescanFile(ctx context.Context, id string) (*RescanResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/analyse", EndpointFiles, id)

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

// GetFileDownloadURL gets a download URL for a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/download_url
// https://docs.virustotal.com/reference/files-download-url
func (s *Service) GetFileDownloadURL(ctx context.Context, id string) (*DownloadURLResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/download_url", EndpointFiles, id)

	var result DownloadURLResponse
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

// DownloadFile downloads a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/download
// https://docs.virustotal.com/reference/files-download
func (s *Service) DownloadFile(ctx context.Context, id string) (*DownloadURLResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/download", EndpointFiles, id)

	var result DownloadURLResponse
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

// GetCommentsOnFile retrieves comments on a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/comments
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/files-comments-get
func (s *Service) GetCommentsOnFile(ctx context.Context, id string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointFiles, id)

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

// AddCommentToFile adds a comment to a file
// URL: POST https://www.virustotal.com/api/v3/files/{id}/comments
// https://docs.virustotal.com/reference/files-comments-post
func (s *Service) AddCommentToFile(ctx context.Context, id string, comment string) (*AddCommentResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}
	if comment == "" {
		return nil, nil, fmt.Errorf("comment text is required")
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointFiles, id)

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

// GetObjectsRelatedToFile retrieves objects related to a file through a specified relationship
// URL: GET https://www.virustotal.com/api/v3/files/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/files-relationships
func (s *Service) GetObjectsRelatedToFile(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointFiles, id, relationship, false)
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

// GetObjectDescriptorsRelatedToFile retrieves lightweight object descriptors related to a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/files-relationships-ids
func (s *Service) GetObjectDescriptorsRelatedToFile(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointFiles, id, relationship, true)
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

// GetSigmaRule retrieves a crowdsourced Sigma rule object
// URL: GET https://www.virustotal.com/api/v3/sigma_rules/{id}
// https://docs.virustotal.com/reference/get-sigma-rules
func (s *Service) GetSigmaRule(ctx context.Context, id string) (*SigmaRuleResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("sigma rule ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSigmaRules, id)

	var result SigmaRuleResponse
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

// GetYARARuleset retrieves a crowdsourced YARA ruleset
// URL: GET https://www.virustotal.com/api/v3/yara_rulesets/{id}
// https://docs.virustotal.com/reference/get-yara-rulesets
func (s *Service) GetYARARuleset(ctx context.Context, id string) (*YARARulesetResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("YARA ruleset ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointYARARulesets, id)

	var result YARARulesetResponse
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

// GetVotesOnFile retrieves votes on a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/votes
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/files-votes-get
func (s *Service) GetVotesOnFile(ctx context.Context, id string, opts *GetVotesOptions) (*VotesResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointFiles, id)

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

// AddVoteToFile adds a vote (harmless or malicious) to a file
// URL: POST https://www.virustotal.com/api/v3/files/{id}/votes
// https://docs.virustotal.com/reference/files-votes-post
func (s *Service) AddVoteToFile(ctx context.Context, id string, verdict string) (*AddVoteResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}
	if verdict == "" {
		return nil, nil, fmt.Errorf("verdict is required")
	}
	if verdict != "harmless" && verdict != "malicious" {
		return nil, nil, fmt.Errorf("verdict must be 'harmless' or 'malicious', got: %s", verdict)
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointFiles, id)

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
