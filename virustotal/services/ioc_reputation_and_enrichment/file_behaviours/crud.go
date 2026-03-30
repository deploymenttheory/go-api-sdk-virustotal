package file_behaviours

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the file behaviours
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference
type Service struct {
	client client.Client
}

// Hash validation regex patterns
var (
	md5Regex    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha1Regex   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	sha256Regex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

// NewService creates a new file behaviours service
func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// =============================================================================
// Hash Validation Helpers
// =============================================================================

// isValidMD5 checks if a string is a valid MD5 hash (32 hexadecimal characters)
func isValidMD5(hash string) bool {
	return md5Regex.MatchString(hash)
}

// isValidSHA1 checks if a string is a valid SHA-1 hash (40 hexadecimal characters)
func isValidSHA1(hash string) bool {
	return sha1Regex.MatchString(hash)
}

// isValidSHA256 checks if a string is a valid SHA-256 hash (64 hexadecimal characters)
func isValidSHA256(hash string) bool {
	return sha256Regex.MatchString(hash)
}

// isValidFileHash checks if a string is a valid file hash (MD5, SHA-1, or SHA-256)
func isValidFileHash(hash string) bool {
	return isValidMD5(hash) || isValidSHA1(hash) || isValidSHA256(hash)
}

// =============================================================================
// File Behaviour Summary Operations
// =============================================================================

// GetFileBehaviourSummaryByHashId retrieves a summary of all behaviours for a file across all sandboxes
// URL: GET https://www.virustotal.com/api/v3/files/{id}/behaviour_summary
// https://docs.virustotal.com/reference/file-all-behaviours-summary
func (s *Service) GetFileBehaviourSummaryByHashId(ctx context.Context, fileID string) (*BehaviourSummaryResponse, *resty.Response, error) {
	if fileID == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}

	if !isValidFileHash(fileID) {
		return nil, nil, fmt.Errorf("file ID must be a valid MD5, SHA-1, or SHA-256 hash")
	}

	endpoint := fmt.Sprintf("%s/%s/behaviour_summary", EndpointFiles, fileID)

	var result BehaviourSummaryResponse
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

// GetAllFileBehavioursSummary retrieves behaviour summaries for multiple files
// URL: GET https://www.virustotal.com/api/v3/files/behaviour_summary?hashes={hashes}
// https://docs.virustotal.com/reference/file-all-behaviours-summary
func (s *Service) GetAllFileBehavioursSummary(ctx context.Context, fileHashes []string) (*BehaviourSummaryResponse, *resty.Response, error) {
	if len(fileHashes) == 0 {
		return nil, nil, fmt.Errorf("at least one file hash is required")
	}

	for i, hash := range fileHashes {
		if !isValidFileHash(hash) {
			return nil, nil, fmt.Errorf("file hash at index %d must be a valid MD5, SHA-1, or SHA-256 hash", i)
		}
	}

	endpoint := fmt.Sprintf("%s/behaviour_summary", EndpointFiles)

	var result BehaviourSummaryResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetQueryParam("hashes", strings.Join(fileHashes, ",")).
		SetResult(&result).
		Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// MITRE ATT&CK Operations
// =============================================================================

// GetFileMitreAttackTrees retrieves a summary of all MITRE ATT&CK techniques observed in a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/behaviour_mitre_trees
// https://docs.virustotal.com/reference/get-a-summary-of-all-mitre-attck-techniques-observed-in-a-file
func (s *Service) GetFileMitreAttackTrees(ctx context.Context, fileID string) (*MitreTreesResponse, *resty.Response, error) {
	if fileID == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}

	if !isValidFileHash(fileID) {
		return nil, nil, fmt.Errorf("file ID must be a valid MD5, SHA-1, or SHA-256 hash")
	}

	endpoint := fmt.Sprintf("%s/%s/behaviour_mitre_trees", EndpointFiles, fileID)

	var result MitreTreesResponse
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
// All Behaviour Reports Operations
// =============================================================================

// GetAllFileBehaviours retrieves all behavior reports for a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/behaviours
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-all-behavior-reports-for-a-file
func (s *Service) GetAllFileBehaviours(ctx context.Context, fileID string, options *GetRelatedObjectsOptions) (*AllBehavioursResponse, *resty.Response, error) {
	if fileID == "" {
		return nil, nil, fmt.Errorf("file ID is required")
	}

	if !isValidFileHash(fileID) {
		return nil, nil, fmt.Errorf("file ID must be a valid MD5, SHA-1, or SHA-256 hash")
	}

	endpoint := fmt.Sprintf("%s/%s/behaviours", EndpointFiles, fileID)

	if options != nil {
		builder := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON)

		if options.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", options.Limit))
		}
		if options.Cursor != "" {
			builder = builder.SetQueryParam("cursor", options.Cursor)
		}

		var result AllBehavioursResponse
		resp, err := builder.SetResult(&result).Get(endpoint)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allReports []BehaviourReport

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		GetPaginated(endpoint, func(pageData []byte) error {
			var pageResponse AllBehavioursResponse
			if err := json.Unmarshal(pageData, &pageResponse); err != nil {
				return fmt.Errorf("failed to unmarshal page: %w", err)
			}
			allReports = append(allReports, pageResponse.Data...)
			return nil
		})

	if err != nil {
		return nil, resp, err
	}

	return &AllBehavioursResponse{
		Data: allReports,
	}, resp, nil
}

// =============================================================================
// Single Behaviour Report Operations
// =============================================================================

// GetFileBehaviour retrieves a specific behaviour report by sandbox ID
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}
// https://docs.virustotal.com/reference/get-file-behaviour-id
func (s *Service) GetFileBehaviour(ctx context.Context, sandboxID string) (*BehaviourReportResponse, *resty.Response, error) {
	if sandboxID == "" {
		return nil, nil, fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointFileBehaviours, sandboxID)

	var result BehaviourReportResponse
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
// Related Objects Operations
// =============================================================================

// GetObjectsRelatedToFileBehaviour retrieves objects related to a behaviour report
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-file-behaviours-relationship
func (s *Service) GetObjectsRelatedToFileBehaviour(ctx context.Context, sandboxID string, relationship string, options *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if sandboxID == "" {
		return nil, nil, fmt.Errorf("sandbox ID is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointFileBehaviours, sandboxID, relationship, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	if options != nil {
		builder := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON)

		if options.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", options.Limit))
		}
		if options.Cursor != "" {
			builder = builder.SetQueryParam("cursor", options.Cursor)
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

// =============================================================================
// Object Descriptors Operations
// =============================================================================

// GetObjectDescriptorsForFileBehaviour retrieves object descriptors for a behaviour report relationship
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-file-behaviours-relationship-descriptor
func (s *Service) GetObjectDescriptorsForFileBehaviour(ctx context.Context, sandboxID string, relationship string, options *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *resty.Response, error) {
	if sandboxID == "" {
		return nil, nil, fmt.Errorf("sandbox ID is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointFileBehaviours, sandboxID, relationship, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	if options != nil {
		builder := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON)

		if options.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", options.Limit))
		}
		if options.Cursor != "" {
			builder = builder.SetQueryParam("cursor", options.Cursor)
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
// Report Format Operations (HTML, EVTX, PCAP, Memdump)
// =============================================================================

// GetFileBehaviourHTML retrieves the HTML report for a behaviour
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/html
// https://docs.virustotal.com/reference/get-file-behaviours-html
func (s *Service) GetFileBehaviourHTML(ctx context.Context, sandboxID string) (string, *resty.Response, error) {
	if sandboxID == "" {
		return "", nil, fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/html", EndpointFileBehaviours, sandboxID)

	resp, body, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.TextHTML).
		GetBytes(endpoint)
	if err != nil {
		return "", resp, err
	}

	return string(body), resp, nil
}

// GetFileBehaviourEVTX retrieves the EVTX file for a behaviour
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/evtx
// https://docs.virustotal.com/reference/get-file-behaviours-evtx
func (s *Service) GetFileBehaviourEVTX(ctx context.Context, sandboxID string) ([]byte, *resty.Response, error) {
	if sandboxID == "" {
		return nil, nil, fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/evtx", EndpointFileBehaviours, sandboxID)

	resp, body, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationOctetStream).
		GetBytes(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return body, resp, nil
}

// GetFileBehaviourPCAP retrieves the PCAP file for a behaviour
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/pcap
// https://docs.virustotal.com/reference/get-file-behaviours-pcap
func (s *Service) GetFileBehaviourPCAP(ctx context.Context, sandboxID string) ([]byte, *resty.Response, error) {
	if sandboxID == "" {
		return nil, nil, fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/pcap", EndpointFileBehaviours, sandboxID)

	resp, body, err := s.client.NewRequest(ctx).
		SetHeader("Accept", "application/vnd.tcpdump.pcap").
		GetBytes(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return body, resp, nil
}

// GetFileBehaviourMemdump retrieves the memory dump for a behaviour
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/memdump
// https://docs.virustotal.com/reference/get-file-behaviours-memdump
func (s *Service) GetFileBehaviourMemdump(ctx context.Context, sandboxID string) ([]byte, *resty.Response, error) {
	if sandboxID == "" {
		return nil, nil, fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/memdump", EndpointFileBehaviours, sandboxID)

	resp, body, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationOctetStream).
		GetBytes(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return body, resp, nil
}
