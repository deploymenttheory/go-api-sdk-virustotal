package saved_searches

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service implements the SavedSearches operations
type Service struct {
	client client.Client
}

func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// =============================================================================
// List Saved Searches Operations
// =============================================================================

// ListSavedSearches retrieves a list of saved searches
// URL: GET https://www.virustotal.com/api/v3/saved_searches
// https://docs.virustotal.com/reference/list-saved-searches
func (s *Service) ListSavedSearches(ctx context.Context, opts *ListSavedSearchesOptions) (*ListSavedSearchesResponse, *resty.Response, error) {
	endpoint := EndpointSavedSearches

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON)

	if opts != nil {
		if opts.Filter != "" {
			builder = builder.SetQueryParam("filter", opts.Filter)
		}
		if opts.Order != "" {
			builder = builder.SetQueryParam("order", opts.Order)
		}
		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}
		if opts.Relationships != "" {
			builder = builder.SetQueryParam("relationships", opts.Relationships)
		}
		if opts.Attributes != "" {
			builder = builder.SetQueryParam("attributes", opts.Attributes)
		}
	}

	var result ListSavedSearchesResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// Get Saved Search Operations
// =============================================================================

// GetSavedSearch retrieves a saved search by its ID
// URL: GET https://www.virustotal.com/api/v3/saved_searches/{id}
// https://docs.virustotal.com/reference/get-saved-searches
func (s *Service) GetSavedSearch(ctx context.Context, searchID string, opts *GetSavedSearchOptions) (*GetSavedSearchResponse, *resty.Response, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSavedSearches, searchID)

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON)

	if opts != nil {
		if opts.Relationships != "" {
			builder = builder.SetQueryParam("relationships", opts.Relationships)
		}
		if opts.Attributes != "" {
			builder = builder.SetQueryParam("attributes", opts.Attributes)
		}
	}

	var result GetSavedSearchResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// Create Saved Search Operations
// =============================================================================

// CreateSavedSearch creates a new saved search
// URL: POST https://www.virustotal.com/api/v3/saved_searches
// https://docs.virustotal.com/reference/create-saved-searches
func (s *Service) CreateSavedSearch(ctx context.Context, attributes SavedSearchAttributes) (*CreateSavedSearchResponse, *resty.Response, error) {
	endpoint := EndpointSavedSearches

	requestBody := CreateSavedSearchRequest{
		Data: SavedSearchData{
			Type:       ObjectTypeSavedSearch,
			Attributes: attributes,
		},
	}

	var result CreateSavedSearchResponse
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
// Update Saved Search Operations
// =============================================================================

// UpdateSavedSearch updates an existing saved search
// URL: PATCH https://www.virustotal.com/api/v3/saved_searches/{id}
// https://docs.virustotal.com/reference/update-saved-searches
func (s *Service) UpdateSavedSearch(ctx context.Context, searchID string, attributes SavedSearchAttributes) (*UpdateSavedSearchResponse, *resty.Response, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSavedSearches, searchID)

	requestBody := UpdateSavedSearchRequest{
		Data: SavedSearchData{
			Type:       ObjectTypeSavedSearch,
			Attributes: attributes,
		},
	}

	var result UpdateSavedSearchResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(requestBody).
		SetResult(&result).
		Patch(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// Delete Saved Search Operations
// =============================================================================

// DeleteSavedSearch deletes a saved search
// URL: DELETE https://www.virustotal.com/api/v3/saved_searches/{id}
// https://docs.virustotal.com/reference/delete-saved-searches
func (s *Service) DeleteSavedSearch(ctx context.Context, searchID string) (*resty.Response, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSavedSearches, searchID)

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		Delete(endpoint)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// =============================================================================
// Share Access Operations
// =============================================================================

// ShareSavedSearch grants access to a saved search
// URL: POST https://www.virustotal.com/api/v3/saved_searches/{id}/relationship/{access}
// https://docs.virustotal.com/reference/share-saved-searches
func (s *Service) ShareSavedSearch(ctx context.Context, searchID string, accessType string, entities []AccessEntity) (*resty.Response, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, err
	}

	if err := ValidateAccessType(accessType); err != nil {
		return nil, err
	}

	if len(entities) == 0 {
		return nil, fmt.Errorf("at least one entity is required")
	}

	// Validate all entities
	for i, entity := range entities {
		if err := ValidateObjectType(entity.Type); err != nil {
			return nil, fmt.Errorf("entity %d: %w", i, err)
		}
		if entity.ID == "" {
			return nil, fmt.Errorf("entity %d: ID cannot be empty", i)
		}
	}

	endpoint := fmt.Sprintf("%s/%s/relationship/%s", EndpointSavedSearches, searchID, accessType)

	requestBody := ShareAccessRequest{
		Data: entities,
	}

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(requestBody).
		Post(endpoint)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// =============================================================================
// Revoke Access Operations
// =============================================================================

// RevokeSavedSearchAccess revokes access to a saved search
// URL: DELETE https://www.virustotal.com/api/v3/saved_searches/{id}/relationship/{access}
// https://docs.virustotal.com/reference/revoke-saved-searches-access
func (s *Service) RevokeSavedSearchAccess(ctx context.Context, searchID string, accessType string, entities []AccessEntity) (*resty.Response, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, err
	}

	if err := ValidateAccessType(accessType); err != nil {
		return nil, err
	}

	if len(entities) == 0 {
		return nil, fmt.Errorf("at least one entity is required")
	}

	// Validate all entities
	for i, entity := range entities {
		if err := ValidateObjectType(entity.Type); err != nil {
			return nil, fmt.Errorf("entity %d: %w", i, err)
		}
		if entity.ID == "" {
			return nil, fmt.Errorf("entity %d: ID cannot be empty", i)
		}
	}

	endpoint := fmt.Sprintf("%s/%s/relationship/%s", EndpointSavedSearches, searchID, accessType)

	requestBody := ShareAccessRequest{
		Data: entities,
	}

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(requestBody).
		Delete(endpoint)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// =============================================================================
// Related Objects Operations
// =============================================================================

// GetObjectsRelatedToSavedSearch retrieves objects related to a saved search
// URL: GET https://www.virustotal.com/api/v3/saved_searches/{id}/{relationship}
// https://docs.virustotal.com/reference/get-saved-searches-relationships
func (s *Service) GetObjectsRelatedToSavedSearch(ctx context.Context, searchID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, nil, err
	}

	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointSavedSearches, searchID, relationship, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON)

	if opts != nil {
		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}
	}

	var result RelatedObjectsResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetObjectDescriptorsRelatedToSavedSearch retrieves object descriptors related to a saved search
// URL: GET https://www.virustotal.com/api/v3/saved_searches/{id}/relationships/{relationship}
// https://docs.virustotal.com/reference/get-saved-searches-related-descriptors
func (s *Service) GetObjectDescriptorsRelatedToSavedSearch(ctx context.Context, searchID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *resty.Response, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, nil, err
	}

	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointSavedSearches, searchID, relationship, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON)

	if opts != nil {
		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}
	}

	var result ObjectDescriptorsResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
