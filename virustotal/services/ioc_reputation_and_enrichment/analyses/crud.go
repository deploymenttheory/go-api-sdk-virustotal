package analyses

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the analyses, submissions, and operations
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference/analyses-api
type Service struct {
	client client.Client
}

// NewService creates a new analyses service
func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// GetAnalysis retrieves an analysis object by its ID
// URL: GET https://www.virustotal.com/api/v3/analyses/{id}
// https://docs.virustotal.com/reference/analysis
func (s *Service) GetAnalysis(ctx context.Context, id string) (*AnalysisResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("analysis ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointAnalyses, id)

	var result AnalysisResponse
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

// GetObjectsRelatedToAnalysis retrieves objects related to an analysis
// URL: GET https://www.virustotal.com/api/v3/analyses/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/analyses-get-objects
func (s *Service) GetObjectsRelatedToAnalysis(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("analysis ID is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	// Use RelationshipBuilder to construct the endpoint for full objects
	endpoint, err := client.BuildRelationshipEndpoint(EndpointAnalyses, id, relationship, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	// The "item" relationship returns a single object, not an array
	if relationship == "item" {
		var singleResult SingleRelatedObjectResponse
		resp, err := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON).
			SetResult(&singleResult).
			Get(endpoint)
		if err != nil {
			return nil, resp, err
		}

		// Convert single object response to array response for consistency
		return &RelatedObjectsResponse{
			Data:  []RelatedObject{singleResult.Data},
			Links: singleResult.Links,
			Meta:  singleResult.Meta,
		}, resp, nil
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

// GetObjectDescriptorsRelatedToAnalysis retrieves object descriptors (IDs only) related to an analysis
// URL: GET https://www.virustotal.com/api/v3/analyses/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/analyses-get-descriptors
func (s *Service) GetObjectDescriptorsRelatedToAnalysis(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("analysis ID is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointAnalyses, id, relationship, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	// The "item" relationship returns a single object, not an array
	if relationship == "item" {
		var singleResult SingleObjectDescriptorResponse
		resp, err := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON).
			SetResult(&singleResult).
			Get(endpoint)
		if err != nil {
			return nil, resp, err
		}

		// Convert single object response to array response for consistency
		return &RelatedObjectDescriptorsResponse{
			Data:  []ObjectDescriptor{singleResult.Data},
			Links: singleResult.Links,
			Meta:  singleResult.Meta,
		}, resp, nil
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

// GetSubmission retrieves a submission object by its ID
// URL: GET https://www.virustotal.com/api/v3/submissions/{id}
// https://docs.virustotal.com/reference/get-submission
func (s *Service) GetSubmission(ctx context.Context, id string) (*SubmissionResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("submission ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSubmissions, id)

	var result SubmissionResponse
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

// GetOperation retrieves an operation object by its ID
// URL: GET https://www.virustotal.com/api/v3/operations/{id}
// https://docs.virustotal.com/reference/get-operations-id
func (s *Service) GetOperation(ctx context.Context, id string) (*OperationResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("operation ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointOperations, id)

	var result OperationResponse
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
