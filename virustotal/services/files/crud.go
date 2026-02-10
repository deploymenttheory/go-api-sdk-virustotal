package files

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// FilesServiceInterface defines the interface for file operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	FilesServiceInterface interface {
		// UploadFile uploads and analyses a file
		//
		// Uploads a file to VirusTotal for analysis. Returns an analysis ID that can be used to retrieve
		// the results. Files must be smaller than 32MB. For larger files, use GetUploadURL.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-scan
		UploadFile(ctx context.Context, request *UploadFileRequest) (*UploadFileResponse, error)

		// GetUploadURL gets a URL for uploading files larger than 32MB
		//
		// Returns a special upload URL that can be used to upload files up to 650MB.
		// Each URL can only be used once and expires after 1 hour.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-upload-url
		GetUploadURL(ctx context.Context) (*UploadURLResponse, error)

		// GetFileReport retrieves information about a file
		//
		// Returns comprehensive information about a file including detection results, metadata,
		// PE information, signatures, and more. The file ID can be any hash (MD5, SHA1, SHA256).
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/file-info
		GetFileReport(ctx context.Context, id string) (*FileResponse, error)

		// RescanFile requests a file rescan (re-analysis)
		//
		// Reanalyses a file already in VirusTotal without uploading it again. Returns an analysis ID
		// that can be used to retrieve the updated results.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-analyse
		RescanFile(ctx context.Context, id string) (*RescanResponse, error)

		// GetFileDownloadURL gets a download URL for a file
		//
		// Returns a signed URL from where the file can be downloaded. Getting the URL counts as a file
		// download in quota. The URL expires after 1 hour. Requires special privileges.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-download-url
		GetFileDownloadURL(ctx context.Context, id string) (*DownloadURLResponse, error)

		// DownloadFile downloads a file
		//
		// Returns a redirect URL to download the file. Similar to GetFileDownloadURL but redirects
		// directly. The URL can be reused for 1 hour. Requires premium privileges.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-download
		DownloadFile(ctx context.Context, id string) (*DownloadURLResponse, error)

		// GetCommentsOnFile retrieves comments on a file
		//
		// Returns a list of comments posted by the VirusTotal community about the file.
		// Comments may include tags extracted from words starting with #. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-comments-get
		GetCommentsOnFile(ctx context.Context, id string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error)

		// AddCommentToFile adds a comment to a file
		//
		// Posts a comment for a file. Words starting with # in the comment text are automatically
		// converted to tags. Returns the created comment object with its assigned ID and creation date.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-comments-post
		AddCommentToFile(ctx context.Context, id string, comment string) (*AddCommentResponse, error)

		// GetObjectsRelatedToFile retrieves objects related to a file
		//
		// Returns objects related to a file based on the specified relationship type.
		// Supported relationships include: contacted_domains, contacted_ips, contacted_urls,
		// dropped_files, bundled_files, and more. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-relationships
		GetObjectsRelatedToFile(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error)

		// GetObjectDescriptorsRelatedToFile retrieves object descriptors (IDs only) related to a file
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		// Supported relationships are the same as GetObjectsRelatedToFile.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-relationships-ids
		GetObjectDescriptorsRelatedToFile(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, error)

		// GetSigmaRule retrieves a crowdsourced Sigma rule object
		//
		// Returns information about a Sigma rule used in crowdsourced analysis results.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-sigma-rules
		GetSigmaRule(ctx context.Context, id string) (*SigmaRuleResponse, error)

		// GetYARARuleset retrieves a crowdsourced YARA ruleset
		//
		// Returns information about a YARA ruleset used in crowdsourced analysis results.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-yara-rulesets
		GetYARARuleset(ctx context.Context, id string) (*YARARulesetResponse, error)

		// GetVotesOnFile retrieves votes on a file
		//
		// Returns a list of votes from the VirusTotal community on whether the file is harmless or malicious.
		// Each vote includes the verdict, date, and value. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-votes-get
		GetVotesOnFile(ctx context.Context, id string, opts *GetVotesOptions) (*VotesResponse, error)

		// AddVoteToFile adds a vote to a file
		//
		// Posts a vote for a file. The verdict must be either "harmless" or "malicious".
		// Returns the created vote object with its assigned ID, creation date, and value.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/files-votes-post
		AddVoteToFile(ctx context.Context, id string, verdict string) (*AddVoteResponse, error)
	}

	// Service handles communication with the files
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	Service struct {
		client interfaces.HTTPClient
	}
)

// Ensure Service implements FilesServiceInterface
var _ FilesServiceInterface = (*Service)(nil)

// NewService creates a new files service
func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// UploadFile uploads and analyses a file
// URL: POST https://www.virustotal.com/api/v3/files
// https://docs.virustotal.com/reference/files-scan
func (s *Service) UploadFile(ctx context.Context, request *UploadFileRequest) (*UploadFileResponse, error) {
	if request == nil || request.File == nil {
		return nil, fmt.Errorf("file is required")
	}
	if request.Filename == "" {
		return nil, fmt.Errorf("filename is required")
	}

	endpoint := EndpointFiles

	headers := map[string]string{
		"Accept": "application/json",
	}

	var formFields map[string]string
	if request.Password != "" {
		formFields = map[string]string{
			"password": request.Password,
		}
	}

	var result UploadFileResponse
	err := s.client.PostMultipart(ctx, endpoint, "file", request.Filename, request.File, request.FileSize, formFields, headers, request.ProgressCallback, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetUploadURL gets a URL for uploading files larger than 32MB
// URL: GET https://www.virustotal.com/api/v3/files/upload_url
// https://docs.virustotal.com/reference/files-upload-url
func (s *Service) GetUploadURL(ctx context.Context) (*UploadURLResponse, error) {
	endpoint := fmt.Sprintf("%s/upload_url", EndpointFiles)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result UploadURLResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetFileReport retrieves information about a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}
// https://docs.virustotal.com/reference/file-info
func (s *Service) GetFileReport(ctx context.Context, id string) (*FileResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointFiles, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result FileResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// RescanFile requests a file rescan (re-analysis)
// URL: POST https://www.virustotal.com/api/v3/files/{id}/analyse
// https://docs.virustotal.com/reference/files-analyse
func (s *Service) RescanFile(ctx context.Context, id string) (*RescanResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/analyse", EndpointFiles, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result RescanResponse
	err := s.client.Post(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetFileDownloadURL gets a download URL for a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/download_url
// https://docs.virustotal.com/reference/files-download-url
func (s *Service) GetFileDownloadURL(ctx context.Context, id string) (*DownloadURLResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/download_url", EndpointFiles, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result DownloadURLResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// DownloadFile downloads a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/download
// https://docs.virustotal.com/reference/files-download
func (s *Service) DownloadFile(ctx context.Context, id string) (*DownloadURLResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/download", EndpointFiles, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result DownloadURLResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetCommentsOnFile retrieves comments on a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/comments
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/files-comments-get
func (s *Service) GetCommentsOnFile(ctx context.Context, id string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointFiles, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	// Manual Pagination Mode: opts provided means single page request
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

	// Default Paginated GET: Automatically fetch all pages
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

// AddCommentToFile adds a comment to a file
// URL: POST https://www.virustotal.com/api/v3/files/{id}/comments
// https://docs.virustotal.com/reference/files-comments-post
func (s *Service) AddCommentToFile(ctx context.Context, id string, comment string) (*AddCommentResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}
	if comment == "" {
		return nil, fmt.Errorf("comment text is required")
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

// GetObjectsRelatedToFile retrieves objects related to a file through a specified relationship
// URL: GET https://www.virustotal.com/api/v3/files/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/files-relationships
func (s *Service) GetObjectsRelatedToFile(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint := fmt.Sprintf("%s/%s/%s", EndpointFiles, id, relationship)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	// Manual Pagination Mode: opts provided means single page request
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

	// Default Paginated GET: Automatically fetch all pages
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

// GetObjectDescriptorsRelatedToFile retrieves lightweight object descriptors related to a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/files-relationships-ids
func (s *Service) GetObjectDescriptorsRelatedToFile(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint := fmt.Sprintf("%s/%s/relationships/%s", EndpointFiles, id, relationship)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	// Manual Pagination Mode: opts provided means single page request
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

	// Default Paginated GET: Automatically fetch all pages
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

// GetSigmaRule retrieves a crowdsourced Sigma rule object
// URL: GET https://www.virustotal.com/api/v3/sigma_rules/{id}
// https://docs.virustotal.com/reference/get-sigma-rules
func (s *Service) GetSigmaRule(ctx context.Context, id string) (*SigmaRuleResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("sigma rule ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSigmaRules, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result SigmaRuleResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetYARARuleset retrieves a crowdsourced YARA ruleset
// URL: GET https://www.virustotal.com/api/v3/yara_rulesets/{id}
// https://docs.virustotal.com/reference/get-yara-rulesets
func (s *Service) GetYARARuleset(ctx context.Context, id string) (*YARARulesetResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("YARA ruleset ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointYARARulesets, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result YARARulesetResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetVotesOnFile retrieves votes on a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/votes
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/files-votes-get
func (s *Service) GetVotesOnFile(ctx context.Context, id string, opts *GetVotesOptions) (*VotesResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/votes", EndpointFiles, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	// Manual Pagination Mode: opts provided means single page request
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

	// Default Paginated GET: Automatically fetch all pages
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

// AddVoteToFile adds a vote (harmless or malicious) to a file
// URL: POST https://www.virustotal.com/api/v3/files/{id}/votes
// https://docs.virustotal.com/reference/files-votes-post
func (s *Service) AddVoteToFile(ctx context.Context, id string, verdict string) (*AddVoteResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("file ID is required")
	}
	if verdict == "" {
		return nil, fmt.Errorf("verdict is required")
	}
	if verdict != "harmless" && verdict != "malicious" {
		return nil, fmt.Errorf("verdict must be 'harmless' or 'malicious', got: %s", verdict)
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
