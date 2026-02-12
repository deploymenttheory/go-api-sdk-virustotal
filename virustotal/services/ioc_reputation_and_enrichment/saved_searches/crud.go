package saved_searches

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// SavedSearchesServiceInterface defines the interface for saved searches operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/saved-searches
	SavedSearchesServiceInterface interface {
		// ListSavedSearches retrieves a list of saved searches
		//
		// Returns saved searches the user has access to as owner, editor, or viewer.
		// Supports filtering, ordering, and pagination through options.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/list-saved-searches
		ListSavedSearches(ctx context.Context, opts *ListSavedSearchesOptions) (*ListSavedSearchesResponse, error)

		// GetSavedSearch retrieves a saved search by its ID
		//
		// Returns the full details of a saved search object identified by its ID.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-saved-searches
		GetSavedSearch(ctx context.Context, searchID string, opts *GetSavedSearchOptions) (*GetSavedSearchResponse, error)

		// CreateSavedSearch creates a new saved search
		//
		// Creates a saved search with the specified attributes. The user automatically
		// becomes the owner of the saved search. The private field determines accessibility.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/create-saved-searches
		CreateSavedSearch(ctx context.Context, attributes SavedSearchAttributes) (*CreateSavedSearchResponse, error)

		// UpdateSavedSearch updates an existing saved search
		//
		// Modifies the attributes of an existing saved search. Restricted to the owner
		// and editors of the saved search.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/update-saved-searches
		UpdateSavedSearch(ctx context.Context, searchID string, attributes SavedSearchAttributes) (*UpdateSavedSearchResponse, error)

		// DeleteSavedSearch deletes a saved search
		//
		// Permanently removes a saved search. Restricted to the owner of the saved search.
		// Upon deletion, the search is no longer accessible to any users.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/delete-saved-searches
		DeleteSavedSearch(ctx context.Context, searchID string) error

		// ShareSavedSearch grants access to a saved search
		//
		// Grants viewer or editor permissions to users or groups for a saved search.
		// Restricted to the owner and editors of the saved search.
		// Editor privileges can only be granted to members of the same group as the owner.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/share-saved-searches
		ShareSavedSearch(ctx context.Context, searchID string, accessType string, entities []AccessEntity) error

		// RevokeSavedSearchAccess revokes access to a saved search
		//
		// Revokes saved search access for specific users or groups. Restricted to
		// the owner and editors of the saved search.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/revoke-saved-searches-access
		RevokeSavedSearchAccess(ctx context.Context, searchID string, accessType string, entities []AccessEntity) error

		// GetObjectsRelatedToSavedSearch retrieves objects related to a saved search
		//
		// Returns objects related to a saved search based on the specified relationship type.
		// Supported relationships include: owner, editors, viewers. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-saved-searches-relationships
		GetObjectsRelatedToSavedSearch(ctx context.Context, searchID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error)

		// GetObjectDescriptorsRelatedToSavedSearch retrieves object descriptors related to a saved search
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		// Supported relationships are the same as GetObjectsRelatedToSavedSearch.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-saved-searches-related-descriptors
		GetObjectDescriptorsRelatedToSavedSearch(ctx context.Context, searchID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, error)
	}

	// Service implements the SavedSearchesServiceInterface
	Service struct {
		client interfaces.HTTPClient
	}
)

var _ SavedSearchesServiceInterface = (*Service)(nil)

func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// =============================================================================
// List Saved Searches Operations
// =============================================================================

// ListSavedSearches retrieves a list of saved searches
// URL: GET https://www.virustotal.com/api/v3/saved_searches
// https://docs.virustotal.com/reference/list-saved-searches
func (s *Service) ListSavedSearches(ctx context.Context, opts *ListSavedSearchesOptions) (*ListSavedSearchesResponse, error) {
	endpoint := EndpointSavedSearches

	queryParams := make(map[string]string)
	if opts != nil {
		if opts.Filter != "" {
			queryParams["filter"] = opts.Filter
		}
		if opts.Order != "" {
			queryParams["order"] = opts.Order
		}
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}
		if opts.Relationships != "" {
			queryParams["relationships"] = opts.Relationships
		}
		if opts.Attributes != "" {
			queryParams["attributes"] = opts.Attributes
		}
	}

	headers := map[string]string{
		"Accept": "application/json",
	}

	var result ListSavedSearchesResponse
	err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// Get Saved Search Operations
// =============================================================================

// GetSavedSearch retrieves a saved search by its ID
// URL: GET https://www.virustotal.com/api/v3/saved_searches/{id}
// https://docs.virustotal.com/reference/get-saved-searches
func (s *Service) GetSavedSearch(ctx context.Context, searchID string, opts *GetSavedSearchOptions) (*GetSavedSearchResponse, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSavedSearches, searchID)

	queryParams := make(map[string]string)
	if opts != nil {
		if opts.Relationships != "" {
			queryParams["relationships"] = opts.Relationships
		}
		if opts.Attributes != "" {
			queryParams["attributes"] = opts.Attributes
		}
	}

	headers := map[string]string{
		"Accept": "application/json",
	}

	var result GetSavedSearchResponse
	err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// Create Saved Search Operations
// =============================================================================

// CreateSavedSearch creates a new saved search
// URL: POST https://www.virustotal.com/api/v3/saved_searches
// https://docs.virustotal.com/reference/create-saved-searches
func (s *Service) CreateSavedSearch(ctx context.Context, attributes SavedSearchAttributes) (*CreateSavedSearchResponse, error) {
	endpoint := EndpointSavedSearches

	requestBody := CreateSavedSearchRequest{
		Data: SavedSearchData{
			Type:       ObjectTypeSavedSearch,
			Attributes: attributes,
		},
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result CreateSavedSearchResponse
	err := s.client.Post(ctx, endpoint, requestBody, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// Update Saved Search Operations
// =============================================================================

// UpdateSavedSearch updates an existing saved search
// URL: PATCH https://www.virustotal.com/api/v3/saved_searches/{id}
// https://docs.virustotal.com/reference/update-saved-searches
func (s *Service) UpdateSavedSearch(ctx context.Context, searchID string, attributes SavedSearchAttributes) (*UpdateSavedSearchResponse, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSavedSearches, searchID)

	requestBody := UpdateSavedSearchRequest{
		Data: SavedSearchData{
			Type:       ObjectTypeSavedSearch,
			Attributes: attributes,
		},
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result UpdateSavedSearchResponse
	err := s.client.Patch(ctx, endpoint, requestBody, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// Delete Saved Search Operations
// =============================================================================

// DeleteSavedSearch deletes a saved search
// URL: DELETE https://www.virustotal.com/api/v3/saved_searches/{id}
// https://docs.virustotal.com/reference/delete-saved-searches
func (s *Service) DeleteSavedSearch(ctx context.Context, searchID string) error {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointSavedSearches, searchID)

	headers := map[string]string{
		"Accept": "application/json",
	}

	err := s.client.Delete(ctx, endpoint, nil, headers, nil)
	if err != nil {
		return err
	}

	return nil
}

// =============================================================================
// Share Access Operations
// =============================================================================

// ShareSavedSearch grants access to a saved search
// URL: POST https://www.virustotal.com/api/v3/saved_searches/{id}/relationship/{access}
// https://docs.virustotal.com/reference/share-saved-searches
func (s *Service) ShareSavedSearch(ctx context.Context, searchID string, accessType string, entities []AccessEntity) error {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return err
	}

	if err := ValidateAccessType(accessType); err != nil {
		return err
	}

	if len(entities) == 0 {
		return fmt.Errorf("at least one entity is required")
	}

	// Validate all entities
	for i, entity := range entities {
		if err := ValidateObjectType(entity.Type); err != nil {
			return fmt.Errorf("entity %d: %w", i, err)
		}
		if entity.ID == "" {
			return fmt.Errorf("entity %d: ID cannot be empty", i)
		}
	}

	endpoint := fmt.Sprintf("%s/%s/relationship/%s", EndpointSavedSearches, searchID, accessType)

	requestBody := ShareAccessRequest{
		Data: entities,
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	err := s.client.Post(ctx, endpoint, requestBody, headers, nil)
	if err != nil {
		return err
	}

	return nil
}

// =============================================================================
// Revoke Access Operations
// =============================================================================

// RevokeSavedSearchAccess revokes access to a saved search
// URL: DELETE https://www.virustotal.com/api/v3/saved_searches/{id}/relationship/{access}
// https://docs.virustotal.com/reference/revoke-saved-searches-access
func (s *Service) RevokeSavedSearchAccess(ctx context.Context, searchID string, accessType string, entities []AccessEntity) error {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return err
	}

	if err := ValidateAccessType(accessType); err != nil {
		return err
	}

	if len(entities) == 0 {
		return fmt.Errorf("at least one entity is required")
	}

	// Validate all entities
	for i, entity := range entities {
		if err := ValidateObjectType(entity.Type); err != nil {
			return fmt.Errorf("entity %d: %w", i, err)
		}
		if entity.ID == "" {
			return fmt.Errorf("entity %d: ID cannot be empty", i)
		}
	}

	endpoint := fmt.Sprintf("%s/%s/relationship/%s", EndpointSavedSearches, searchID, accessType)

	requestBody := ShareAccessRequest{
		Data: entities,
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	err := s.client.DeleteWithBody(ctx, endpoint, requestBody, headers, nil)
	if err != nil {
		return err
	}

	return nil
}

// =============================================================================
// Related Objects Operations
// =============================================================================

// GetObjectsRelatedToSavedSearch retrieves objects related to a saved search
// URL: GET https://www.virustotal.com/api/v3/saved_searches/{id}/{relationship}
// https://docs.virustotal.com/reference/get-saved-searches-relationships
func (s *Service) GetObjectsRelatedToSavedSearch(ctx context.Context, searchID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, err
	}

	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointSavedSearches, searchID, relationship, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	queryParams := make(map[string]string)
	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}
	}

	headers := map[string]string{
		"Accept": "application/json",
	}

	var result RelatedObjectsResponse
	err = s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetObjectDescriptorsRelatedToSavedSearch retrieves object descriptors related to a saved search
// URL: GET https://www.virustotal.com/api/v3/saved_searches/{id}/relationships/{relationship}
// https://docs.virustotal.com/reference/get-saved-searches-related-descriptors
func (s *Service) GetObjectDescriptorsRelatedToSavedSearch(ctx context.Context, searchID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, error) {
	if err := ValidateSavedSearchID(searchID); err != nil {
		return nil, err
	}

	if relationship == "" {
		return nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointSavedSearches, searchID, relationship, true)
	if err != nil {
		return nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	queryParams := make(map[string]string)
	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}
	}

	headers := map[string]string{
		"Accept": "application/json",
	}

	var result ObjectDescriptorsResponse
	err = s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
