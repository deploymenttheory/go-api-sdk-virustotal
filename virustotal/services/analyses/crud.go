package analyses

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// AnalysesServiceInterface defines the interface for analyses, submissions, and operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/analyses-api
	AnalysesServiceInterface interface {
		// GetAnalysis retrieves an analysis object by its ID
		//
		// Returns detailed information about a file or URL analysis, including results from
		// all security engines, status, and timestamps. The analysis ID is returned when
		// submitting files or URLs for scanning.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/analysis
		GetAnalysis(ctx context.Context, id string) (*AnalysisResponse, error)

		// GetObjectsRelatedToAnalysis retrieves objects related to an analysis
		//
		// Returns objects related to an analysis based on the specified relationship type.
		// Currently supports: "item" (returns the file or URL that was analyzed).
		// Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/analyses-get-objects
		GetObjectsRelatedToAnalysis(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error)

		// GetObjectDescriptorsRelatedToAnalysis retrieves object descriptors (IDs only) related to an analysis
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		// Supported relationships are the same as GetObjectsRelatedToAnalysis.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/analyses-get-descriptors
		GetObjectDescriptorsRelatedToAnalysis(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, error)

		// GetSubmission retrieves a submission object by its ID
		//
		// Returns metadata about when and how an item was submitted to VirusTotal.
		// Premium API features include detailed information like submission interface,
		// location, filename, and anonymized submitter token.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-submission
		GetSubmission(ctx context.Context, id string) (*SubmissionResponse, error)

		// GetOperation retrieves an operation object by its ID
		//
		// Returns the status of an asynchronous operation. Operations represent long-running
		// tasks that cannot complete immediately. Poll this endpoint to check if an operation
		// is still running, has finished, or was aborted.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-operations-id
		GetOperation(ctx context.Context, id string) (*OperationResponse, error)
	}

	// Service handles communication with the analyses, submissions, and operations
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/analyses-api
	Service struct {
		client interfaces.HTTPClient
	}
)

// Ensure Service implements AnalysesServiceInterface
var _ AnalysesServiceInterface = (*Service)(nil)

// NewService creates a new analyses service
func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// GetAnalysis retrieves an analysis object by its ID
// URL: GET https://www.virustotal.com/api/v3/analyses/{id}
// https://docs.virustotal.com/reference/analysis
func (s *Service) GetAnalysis(ctx context.Context, id string) (*AnalysisResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("analysis ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointAnalyses, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result AnalysisResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetObjectsRelatedToAnalysis retrieves objects related to an analysis
// URL: GET https://www.virustotal.com/api/v3/analyses/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/analyses-get-objects
func (s *Service) GetObjectsRelatedToAnalysis(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("analysis ID is required")
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	// Use RelationshipBuilder to construct the endpoint for full objects
	endpoint, err := client.BuildRelationshipEndpoint(EndpointAnalyses, id, relationship, false)
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

// GetObjectDescriptorsRelatedToAnalysis retrieves object descriptors (IDs only) related to an analysis
// URL: GET https://www.virustotal.com/api/v3/analyses/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/analyses-get-descriptors
func (s *Service) GetObjectDescriptorsRelatedToAnalysis(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("analysis ID is required")
	}
	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	// Use RelationshipBuilder to construct the endpoint for descriptors only
	endpoint, err := client.BuildRelationshipEndpoint(EndpointAnalyses, id, relationship, true)
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

		var result RelatedObjectDescriptorsResponse
		err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, err
		}

		return &result, nil
	}

	var allDescriptors []ObjectDescriptor

	err = s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
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

// GetSubmission retrieves a submission object by its ID
// URL: GET https://www.virustotal.com/api/v3/submissions/{id}
// https://docs.virustotal.com/reference/get-submission
func (s *Service) GetSubmission(ctx context.Context, id string) (*SubmissionResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("submission ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSubmissions, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result SubmissionResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetOperation retrieves an operation object by its ID
// URL: GET https://www.virustotal.com/api/v3/operations/{id}
// https://docs.virustotal.com/reference/get-operations-id
func (s *Service) GetOperation(ctx context.Context, id string) (*OperationResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("operation ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointOperations, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result OperationResponse
	err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
