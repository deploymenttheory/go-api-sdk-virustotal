package file_behaviours

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// FileBehavioursServiceInterface defines the interface for file behaviours operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	FileBehavioursServiceInterface interface {
		// GetFileBehaviourSummaryByHashId retrieves a summary of all behaviours for a file across all sandboxes
		//
		// Returns aggregated behavioural information from all sandbox reports, including process trees,
		// file operations, network activity, registry modifications, and MITRE ATT&CK techniques.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/file-all-behaviours-summary
		GetFileBehaviourSummaryByHashId(ctx context.Context, fileID string) (*BehaviourSummaryResponse, error)

		// GetAllFileBehavioursSummary retrieves behaviour summaries for multiple files
		//
		// Returns aggregated behavioural information for multiple files specified by their hashes.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/file-all-behaviours-summary
		GetAllFileBehavioursSummary(ctx context.Context, fileHashes []string) (*BehaviourSummaryResponse, error)

		// GetFileMitreAttackTrees retrieves a summary of all MITRE ATT&CK techniques observed in a file
		//
		// Returns a hierarchical structure of MITRE ATT&CK tactics and techniques for each sandbox report,
		// organized by sandbox name.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-a-summary-of-all-mitre-attck-techniques-observed-in-a-file
		GetFileMitreAttackTrees(ctx context.Context, fileID string) (*MitreTreesResponse, error)

		// GetAllFileBehaviours retrieves all behavior reports for a file
		//
		// Returns a collection of individual sandbox behaviour reports for a file.
		// Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-all-behavior-reports-for-a-file
		GetAllFileBehaviours(ctx context.Context, fileID string, options *GetRelatedObjectsOptions) (*AllBehavioursResponse, error)

		// GetFileBehaviour retrieves a specific behaviour report by sandbox ID
		//
		// Returns a single behaviour report for a specific sandbox analysis.
		// Sandbox ID format: {file_sha256}_{sandbox_name}
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-file-behaviour-id
		GetFileBehaviour(ctx context.Context, sandboxID string) (*BehaviourReportResponse, error)

		// GetObjectsRelatedToFileBehaviour retrieves objects related to a behaviour report
		//
		// Returns objects related to a behaviour report based on the specified relationship type.
		// Supported relationships include: file, attack_techniques.
		// Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-file-behaviours-relationship
		GetObjectsRelatedToFileBehaviour(ctx context.Context, sandboxID string, relationship string, options *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error)

		// GetObjectDescriptorsForFileBehaviour retrieves object descriptors for a behaviour report relationship
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-file-behaviours-relationship-descriptor
		GetObjectDescriptorsForFileBehaviour(ctx context.Context, sandboxID string, relationship string, options *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, error)

		// GetFileBehaviourHTML retrieves the HTML report for a behaviour
		//
		// Returns a detailed HTML behaviour report for a specific sandbox analysis.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-file-behaviours-html
		GetFileBehaviourHTML(ctx context.Context, sandboxID string) (string, error)

		// GetFileBehaviourEVTX retrieves the EVTX file for a behaviour
		//
		// Returns the Windows Event Log (EVTX) file from a sandbox analysis.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-file-behaviours-evtx
		GetFileBehaviourEVTX(ctx context.Context, sandboxID string) ([]byte, error)

		// GetFileBehaviourPCAP retrieves the PCAP file for a behaviour
		//
		// Returns the network traffic capture (PCAP) file from a sandbox analysis.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-file-behaviours-pcap
		GetFileBehaviourPCAP(ctx context.Context, sandboxID string) ([]byte, error)

		// GetFileBehaviourMemdump retrieves the memory dump for a behaviour
		//
		// Returns the memory dump file from a sandbox analysis.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-file-behaviours-memdump
		GetFileBehaviourMemdump(ctx context.Context, sandboxID string) ([]byte, error)
	}

	// Service handles communication with the file behaviours
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	Service struct {
		client interfaces.HTTPClient
	}
)

// Ensure Service implements FileBehavioursServiceInterface
var _ FileBehavioursServiceInterface = (*Service)(nil)

// Hash validation regex patterns
var (
	md5Regex    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha1Regex   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	sha256Regex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

// NewService creates a new file behaviours service
func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
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
func (s *Service) GetFileBehaviourSummaryByHashId(ctx context.Context, fileID string) (*BehaviourSummaryResponse, error) {
	if fileID == "" {
		return nil, fmt.Errorf("file ID is required")
	}

	if !isValidFileHash(fileID) {
		return nil, fmt.Errorf("file ID must be a valid MD5, SHA-1, or SHA-256 hash")
	}

	endpoint := fmt.Sprintf("%s/%s/behaviour_summary", EndpointFiles, fileID)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result BehaviourSummaryResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetAllFileBehavioursSummary retrieves behaviour summaries for multiple files
// URL: GET https://www.virustotal.com/api/v3/files/behaviour_summary?hashes={hashes}
// https://docs.virustotal.com/reference/file-all-behaviours-summary
func (s *Service) GetAllFileBehavioursSummary(ctx context.Context, fileHashes []string) (*BehaviourSummaryResponse, error) {
	if len(fileHashes) == 0 {
		return nil, fmt.Errorf("at least one file hash is required")
	}

	for i, hash := range fileHashes {
		if !isValidFileHash(hash) {
			return nil, fmt.Errorf("file hash at index %d must be a valid MD5, SHA-1, or SHA-256 hash", i)
		}
	}

	endpoint := fmt.Sprintf("%s/behaviour_summary", EndpointFiles)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := map[string]string{
		"hashes": strings.Join(fileHashes, ","),
	}

	var result BehaviourSummaryResponse
	err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// MITRE ATT&CK Operations
// =============================================================================

// GetFileMitreAttackTrees retrieves a summary of all MITRE ATT&CK techniques observed in a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/behaviour_mitre_trees
// https://docs.virustotal.com/reference/get-a-summary-of-all-mitre-attck-techniques-observed-in-a-file
func (s *Service) GetFileMitreAttackTrees(ctx context.Context, fileID string) (*MitreTreesResponse, error) {
	if fileID == "" {
		return nil, fmt.Errorf("file ID is required")
	}

	if !isValidFileHash(fileID) {
		return nil, fmt.Errorf("file ID must be a valid MD5, SHA-1, or SHA-256 hash")
	}

	endpoint := fmt.Sprintf("%s/%s/behaviour_mitre_trees", EndpointFiles, fileID)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result MitreTreesResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// All Behaviour Reports Operations
// =============================================================================

// GetAllFileBehaviours retrieves all behavior reports for a file
// URL: GET https://www.virustotal.com/api/v3/files/{id}/behaviours
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-all-behavior-reports-for-a-file
func (s *Service) GetAllFileBehaviours(ctx context.Context, fileID string, options *GetRelatedObjectsOptions) (*AllBehavioursResponse, error) {
	if fileID == "" {
		return nil, fmt.Errorf("file ID is required")
	}

	if !isValidFileHash(fileID) {
		return nil, fmt.Errorf("file ID must be a valid MD5, SHA-1, or SHA-256 hash")
	}

	endpoint := fmt.Sprintf("%s/%s/behaviours", EndpointFiles, fileID)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	if options != nil {
		if options.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", options.Limit)
		}
		if options.Cursor != "" {
			queryParams["cursor"] = options.Cursor
		}

		var result AllBehavioursResponse
		err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, err
		}

		return &result, nil
	}

	var allReports []BehaviourReport

	err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
		var pageResponse AllBehavioursResponse
		if err := json.Unmarshal(pageData, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		allReports = append(allReports, pageResponse.Data...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &AllBehavioursResponse{
		Data: allReports,
	}, nil
}

// =============================================================================
// Single Behaviour Report Operations
// =============================================================================

// GetFileBehaviour retrieves a specific behaviour report by sandbox ID
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}
// https://docs.virustotal.com/reference/get-file-behaviour-id
func (s *Service) GetFileBehaviour(ctx context.Context, sandboxID string) (*BehaviourReportResponse, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointFileBehaviours, sandboxID)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result BehaviourReportResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// Related Objects Operations
// =============================================================================

// GetObjectsRelatedToFileBehaviour retrieves objects related to a behaviour report
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-file-behaviours-relationship
func (s *Service) GetObjectsRelatedToFileBehaviour(ctx context.Context, sandboxID string, relationship string, options *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sandbox ID is required")
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint := fmt.Sprintf("%s/%s/%s", EndpointFileBehaviours, sandboxID, relationship)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	if options != nil {
		if options.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", options.Limit)
		}
		if options.Cursor != "" {
			queryParams["cursor"] = options.Cursor
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

// =============================================================================
// Object Descriptors Operations
// =============================================================================

// GetObjectDescriptorsForFileBehaviour retrieves object descriptors for a behaviour report relationship
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-file-behaviours-relationship-descriptor
func (s *Service) GetObjectDescriptorsForFileBehaviour(ctx context.Context, sandboxID string, relationship string, options *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sandbox ID is required")
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint := fmt.Sprintf("%s/%s/relationships/%s", EndpointFileBehaviours, sandboxID, relationship)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	if options != nil {
		if options.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", options.Limit)
		}
		if options.Cursor != "" {
			queryParams["cursor"] = options.Cursor
		}

		var result ObjectDescriptorsResponse
		err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, err
		}

		return &result, nil
	}

	var allDescriptors []ObjectDescriptor

	err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
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
// Report Format Operations (HTML, EVTX, PCAP, Memdump)
// =============================================================================

// GetFileBehaviourHTML retrieves the HTML report for a behaviour
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/html
// https://docs.virustotal.com/reference/get-file-behaviours-html
func (s *Service) GetFileBehaviourHTML(ctx context.Context, sandboxID string) (string, error) {
	if sandboxID == "" {
		return "", fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/html", EndpointFileBehaviours, sandboxID)

	headers := map[string]string{
		"Accept": "text/html",
	}

	body, err := s.client.GetBytes(ctx, endpoint, nil, headers)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// GetFileBehaviourEVTX retrieves the EVTX file for a behaviour
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/evtx
// https://docs.virustotal.com/reference/get-file-behaviours-evtx
func (s *Service) GetFileBehaviourEVTX(ctx context.Context, sandboxID string) ([]byte, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/evtx", EndpointFileBehaviours, sandboxID)

	headers := map[string]string{
		"Accept": "application/octet-stream",
	}

	body, err := s.client.GetBytes(ctx, endpoint, nil, headers)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// GetFileBehaviourPCAP retrieves the PCAP file for a behaviour
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/pcap
// https://docs.virustotal.com/reference/get-file-behaviours-pcap
func (s *Service) GetFileBehaviourPCAP(ctx context.Context, sandboxID string) ([]byte, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/pcap", EndpointFileBehaviours, sandboxID)

	headers := map[string]string{
		"Accept": "application/vnd.tcpdump.pcap",
	}

	body, err := s.client.GetBytes(ctx, endpoint, nil, headers)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// GetFileBehaviourMemdump retrieves the memory dump for a behaviour
// URL: GET https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/memdump
// https://docs.virustotal.com/reference/get-file-behaviours-memdump
func (s *Service) GetFileBehaviourMemdump(ctx context.Context, sandboxID string) ([]byte, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sandbox ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s/memdump", EndpointFileBehaviours, sandboxID)

	headers := map[string]string{
		"Accept": "application/octet-stream",
	}

	body, err := s.client.GetBytes(ctx, endpoint, nil, headers)
	if err != nil {
		return nil, err
	}

	return body, nil
}
