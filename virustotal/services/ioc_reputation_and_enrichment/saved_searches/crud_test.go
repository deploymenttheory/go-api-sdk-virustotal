package saved_searches

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/saved_searches/mocks"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupMockClient creates a test client and activates httpmock
func setupMockClient(t *testing.T) *Service {
	t.Helper()

	// Create test logger
	logger := zap.NewNop()

	// Create base URL for testing
	baseURL := "https://www.virustotal.com/api/v3"

	// Create HTTP client
	apiClient, err := client.NewClient("test-api-key",
		client.WithLogger(logger),
		client.WithBaseURL(baseURL),
	)
	require.NoError(t, err)

	// Activate httpmock
	httpmock.ActivateNonDefault(apiClient.GetHTTPClient().Client())

	// Setup cleanup
	t.Cleanup(func() {
		httpmock.DeactivateAndReset()
	})

	// Create service with the client
	return NewService(apiClient)
}

const testSavedSearchID = "0a49acd622a44982b1986984ba31c15b"

// =============================================================================
// ListSavedSearches Tests
// =============================================================================

// TestUnitListSavedSearches_Success tests successful listing of saved searches
func TestUnitListSavedSearches_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	result, err := service.ListSavedSearches(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "saved_search", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
	assert.NotEmpty(t, result.Data[0].Attributes.Name)
	assert.NotEmpty(t, result.Data[0].Attributes.SearchQuery)
}

// TestUnitListSavedSearches_WithOptions tests listing saved searches with options
func TestUnitListSavedSearches_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	opts := &ListSavedSearchesOptions{
		Limit:  10,
		Filter: "creation_date:2025-10-27+",
		Order:  "last_modification_date-",
	}

	result, err := service.ListSavedSearches(context.Background(), opts)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Greater(t, len(result.Data), 0)
}

// =============================================================================
// GetSavedSearch Tests
// =============================================================================

// TestUnitGetSavedSearch_Success tests successful retrieval of a saved search
func TestUnitGetSavedSearch_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetSavedSearch(context.Background(), testSavedSearchID, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "saved_search", result.Data.Type)
	assert.Equal(t, testSavedSearchID, result.Data.ID)
	assert.NotEmpty(t, result.Data.Attributes.Name)
	assert.NotEmpty(t, result.Data.Attributes.SearchQuery)
}

// TestUnitGetSavedSearch_WithOptions tests getting a saved search with options
func TestUnitGetSavedSearch_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	opts := &GetSavedSearchOptions{
		Relationships: "owner,editors",
		Attributes:    "name,search_query",
	}

	result, err := service.GetSavedSearch(context.Background(), testSavedSearchID, opts)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, testSavedSearchID, result.Data.ID)
}

// TestUnitGetSavedSearch_EmptyID tests error handling for empty ID
func TestUnitGetSavedSearch_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	result, err := service.GetSavedSearch(context.Background(), "", nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot be empty")
}

// TestUnitGetSavedSearch_InvalidID tests error handling for invalid ID
func TestUnitGetSavedSearch_InvalidID(t *testing.T) {
	service := setupMockClient(t)

	result, err := service.GetSavedSearch(context.Background(), "invalid-id", nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "32-character hexadecimal string")
}

// TestUnitGetSavedSearch_NotFound tests error handling for not found saved search
func TestUnitGetSavedSearch_NotFound(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterErrorMocks()

	result, err := service.GetSavedSearch(context.Background(), "00000000000000000000000000000000", nil)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// =============================================================================
// CreateSavedSearch Tests
// =============================================================================

// TestUnitCreateSavedSearch_Success tests successful creation of a saved search
func TestUnitCreateSavedSearch_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	attributes := SavedSearchAttributes{
		Name:        "Test Search",
		Description: "A test search query",
		SearchQuery: "type:file and positives:5+",
		Private:     true,
		Tags:        []string{"test", "malware"},
	}

	result, err := service.CreateSavedSearch(context.Background(), attributes)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "saved_search", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
	assert.NotEmpty(t, result.Data.Attributes.Name)
	assert.NotEmpty(t, result.Data.Attributes.SearchQuery)
}

// TestUnitCreateSavedSearch_MinimalAttributes tests creation with minimal attributes
func TestUnitCreateSavedSearch_MinimalAttributes(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	attributes := SavedSearchAttributes{
		Name:        "Minimal Search",
		SearchQuery: "type:domain",
		Private:     false,
	}

	result, err := service.CreateSavedSearch(context.Background(), attributes)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "saved_search", result.Data.Type)
}

// TestUnitCreateSavedSearch_PublicSearch tests creation of a public search
func TestUnitCreateSavedSearch_PublicSearch(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	attributes := SavedSearchAttributes{
		Name:        "Public Search",
		Description: "A publicly accessible search",
		SearchQuery: "type:ip_address",
		Private:     false,
		Tags:        []string{"public", "ip"},
	}

	result, err := service.CreateSavedSearch(context.Background(), attributes)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "saved_search", result.Data.Type)
}

// =============================================================================
// UpdateSavedSearch Tests
// =============================================================================

// TestUnitUpdateSavedSearch_Success tests successful update of a saved search
func TestUnitUpdateSavedSearch_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	attributes := SavedSearchAttributes{
		Name:        "Updated Search Name",
		Description: "Updated description",
		SearchQuery: "type:file and positives:10+",
		Private:     true,
		Tags:        []string{"updated", "test"},
	}

	result, err := service.UpdateSavedSearch(context.Background(), testSavedSearchID, attributes)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "saved_search", result.Data.Type)
	assert.Equal(t, testSavedSearchID, result.Data.ID)
}

// TestUnitUpdateSavedSearch_EmptyID tests error handling for empty ID
func TestUnitUpdateSavedSearch_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	attributes := SavedSearchAttributes{
		Name:        "Test",
		SearchQuery: "type:file",
	}

	result, err := service.UpdateSavedSearch(context.Background(), "", attributes)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot be empty")
}

// TestUnitUpdateSavedSearch_InvalidID tests error handling for invalid ID
func TestUnitUpdateSavedSearch_InvalidID(t *testing.T) {
	service := setupMockClient(t)

	attributes := SavedSearchAttributes{
		Name:        "Test",
		SearchQuery: "type:file",
	}

	result, err := service.UpdateSavedSearch(context.Background(), "invalid-id", attributes)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "32-character hexadecimal string")
}

// =============================================================================
// DeleteSavedSearch Tests
// =============================================================================

// TestUnitDeleteSavedSearch_Success tests successful deletion of a saved search
func TestUnitDeleteSavedSearch_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	err := service.DeleteSavedSearch(context.Background(), testSavedSearchID)
	require.NoError(t, err)
}

// TestUnitDeleteSavedSearch_EmptyID tests error handling for empty ID
func TestUnitDeleteSavedSearch_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	err := service.DeleteSavedSearch(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

// TestUnitDeleteSavedSearch_InvalidID tests error handling for invalid ID
func TestUnitDeleteSavedSearch_InvalidID(t *testing.T) {
	service := setupMockClient(t)

	err := service.DeleteSavedSearch(context.Background(), "invalid-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "32-character hexadecimal string")
}

// TestUnitDeleteSavedSearch_Forbidden tests error handling for forbidden deletion
func TestUnitDeleteSavedSearch_Forbidden(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterErrorMocks()

	err := service.DeleteSavedSearch(context.Background(), "f60631d600b44a91a8b20cef8c77aeac")
	assert.Error(t, err)
}

// =============================================================================
// ShareSavedSearch Tests
// =============================================================================

// TestUnitShareSavedSearch_ViewersSuccess tests successful sharing with viewers
func TestUnitShareSavedSearch_ViewersSuccess(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	entities := []AccessEntity{
		{
			ID:   "user123",
			Type: ObjectTypeUser,
		},
	}

	err := service.ShareSavedSearch(context.Background(), testSavedSearchID, AccessTypeViewers, entities)
	require.NoError(t, err)
}

// TestUnitShareSavedSearch_EditorsSuccess tests successful sharing with editors
func TestUnitShareSavedSearch_EditorsSuccess(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	entities := []AccessEntity{
		{
			ID:   "group456",
			Type: ObjectTypeGroup,
		},
	}

	err := service.ShareSavedSearch(context.Background(), testSavedSearchID, AccessTypeEditors, entities)
	require.NoError(t, err)
}

// TestUnitShareSavedSearch_MultipleEntities tests sharing with multiple entities
func TestUnitShareSavedSearch_MultipleEntities(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	entities := []AccessEntity{
		{
			ID:   "user123",
			Type: ObjectTypeUser,
		},
		{
			ID:   "user456",
			Type: ObjectTypeUser,
		},
		{
			ID:   "group789",
			Type: ObjectTypeGroup,
		},
	}

	err := service.ShareSavedSearch(context.Background(), testSavedSearchID, AccessTypeViewers, entities)
	require.NoError(t, err)
}

// TestUnitShareSavedSearch_EmptySearchID tests error handling for empty search ID
func TestUnitShareSavedSearch_EmptySearchID(t *testing.T) {
	service := setupMockClient(t)

	entities := []AccessEntity{{ID: "user123", Type: ObjectTypeUser}}

	err := service.ShareSavedSearch(context.Background(), "", AccessTypeViewers, entities)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

// TestUnitShareSavedSearch_InvalidAccessType tests error handling for invalid access type
func TestUnitShareSavedSearch_InvalidAccessType(t *testing.T) {
	service := setupMockClient(t)

	entities := []AccessEntity{{ID: "user123", Type: ObjectTypeUser}}

	err := service.ShareSavedSearch(context.Background(), testSavedSearchID, "invalid", entities)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access type must be one of")
}

// TestUnitShareSavedSearch_EmptyEntities tests error handling for empty entities
func TestUnitShareSavedSearch_EmptyEntities(t *testing.T) {
	service := setupMockClient(t)

	err := service.ShareSavedSearch(context.Background(), testSavedSearchID, AccessTypeViewers, []AccessEntity{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one entity is required")
}

// TestUnitShareSavedSearch_InvalidEntityType tests error handling for invalid entity type
func TestUnitShareSavedSearch_InvalidEntityType(t *testing.T) {
	service := setupMockClient(t)

	entities := []AccessEntity{
		{
			ID:   "test123",
			Type: "invalid_type",
		},
	}

	err := service.ShareSavedSearch(context.Background(), testSavedSearchID, AccessTypeViewers, entities)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "object type must be one of")
}

// TestUnitShareSavedSearch_EmptyEntityID tests error handling for empty entity ID
func TestUnitShareSavedSearch_EmptyEntityID(t *testing.T) {
	service := setupMockClient(t)

	entities := []AccessEntity{
		{
			ID:   "",
			Type: ObjectTypeUser,
		},
	}

	err := service.ShareSavedSearch(context.Background(), testSavedSearchID, AccessTypeViewers, entities)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ID cannot be empty")
}

// =============================================================================
// RevokeSavedSearchAccess Tests
// =============================================================================

// TestUnitRevokeSavedSearchAccess_ViewersSuccess tests successful revoking of viewer access
func TestUnitRevokeSavedSearchAccess_ViewersSuccess(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	entities := []AccessEntity{
		{
			ID:   "user123",
			Type: ObjectTypeUser,
		},
	}

	err := service.RevokeSavedSearchAccess(context.Background(), testSavedSearchID, AccessTypeViewers, entities)
	require.NoError(t, err)
}

// TestUnitRevokeSavedSearchAccess_EditorsSuccess tests successful revoking of editor access
func TestUnitRevokeSavedSearchAccess_EditorsSuccess(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	entities := []AccessEntity{
		{
			ID:   "group456",
			Type: ObjectTypeGroup,
		},
	}

	err := service.RevokeSavedSearchAccess(context.Background(), testSavedSearchID, AccessTypeEditors, entities)
	require.NoError(t, err)
}

// TestUnitRevokeSavedSearchAccess_MultipleEntities tests revoking access for multiple entities
func TestUnitRevokeSavedSearchAccess_MultipleEntities(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	entities := []AccessEntity{
		{
			ID:   "user123",
			Type: ObjectTypeUser,
		},
		{
			ID:   "user456",
			Type: ObjectTypeUser,
		},
	}

	err := service.RevokeSavedSearchAccess(context.Background(), testSavedSearchID, AccessTypeViewers, entities)
	require.NoError(t, err)
}

// TestUnitRevokeSavedSearchAccess_EmptySearchID tests error handling for empty search ID
func TestUnitRevokeSavedSearchAccess_EmptySearchID(t *testing.T) {
	service := setupMockClient(t)

	entities := []AccessEntity{{ID: "user123", Type: ObjectTypeUser}}

	err := service.RevokeSavedSearchAccess(context.Background(), "", AccessTypeViewers, entities)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

// TestUnitRevokeSavedSearchAccess_InvalidAccessType tests error handling for invalid access type
func TestUnitRevokeSavedSearchAccess_InvalidAccessType(t *testing.T) {
	service := setupMockClient(t)

	entities := []AccessEntity{{ID: "user123", Type: ObjectTypeUser}}

	err := service.RevokeSavedSearchAccess(context.Background(), testSavedSearchID, "invalid", entities)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access type must be one of")
}

// TestUnitRevokeSavedSearchAccess_EmptyEntities tests error handling for empty entities
func TestUnitRevokeSavedSearchAccess_EmptyEntities(t *testing.T) {
	service := setupMockClient(t)

	err := service.RevokeSavedSearchAccess(context.Background(), testSavedSearchID, AccessTypeViewers, []AccessEntity{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one entity is required")
}

// =============================================================================
// GetObjectsRelatedToSavedSearch Tests
// =============================================================================

// TestUnitGetObjectsRelatedToSavedSearch_Success tests successful retrieval of related objects
func TestUnitGetObjectsRelatedToSavedSearch_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetObjectsRelatedToSavedSearch(context.Background(), testSavedSearchID, RelationshipOwner, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Greater(t, len(result.Data), 0)
	assert.NotEmpty(t, result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

// TestUnitGetObjectsRelatedToSavedSearch_WithOptions tests retrieval with options
func TestUnitGetObjectsRelatedToSavedSearch_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	opts := &GetRelatedObjectsOptions{
		Limit:  10,
		Cursor: "test-cursor",
	}

	result, err := service.GetObjectsRelatedToSavedSearch(context.Background(), testSavedSearchID, RelationshipOwner, opts)
	require.NoError(t, err)
	require.NotNil(t, result)
}

// TestUnitGetObjectsRelatedToSavedSearch_EmptySearchID tests error handling for empty search ID
func TestUnitGetObjectsRelatedToSavedSearch_EmptySearchID(t *testing.T) {
	service := setupMockClient(t)

	result, err := service.GetObjectsRelatedToSavedSearch(context.Background(), "", RelationshipOwner, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot be empty")
}

// TestUnitGetObjectsRelatedToSavedSearch_EmptyRelationship tests error handling for empty relationship
func TestUnitGetObjectsRelatedToSavedSearch_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	result, err := service.GetObjectsRelatedToSavedSearch(context.Background(), testSavedSearchID, "", nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

// =============================================================================
// GetObjectDescriptorsRelatedToSavedSearch Tests
// =============================================================================

// TestUnitGetObjectDescriptorsRelatedToSavedSearch_Success tests successful retrieval of object descriptors
func TestUnitGetObjectDescriptorsRelatedToSavedSearch_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetObjectDescriptorsRelatedToSavedSearch(context.Background(), testSavedSearchID, RelationshipEditors, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Greater(t, len(result.Data), 0)
	assert.NotEmpty(t, result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

// TestUnitGetObjectDescriptorsRelatedToSavedSearch_WithOptions tests retrieval with options
func TestUnitGetObjectDescriptorsRelatedToSavedSearch_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSavedSearchesMock()
	mockHandler.RegisterMocks()

	opts := &GetRelatedObjectsOptions{
		Limit:  5,
		Cursor: "test-cursor",
	}

	result, err := service.GetObjectDescriptorsRelatedToSavedSearch(context.Background(), testSavedSearchID, RelationshipEditors, opts)
	require.NoError(t, err)
	require.NotNil(t, result)
}

// TestUnitGetObjectDescriptorsRelatedToSavedSearch_EmptySearchID tests error handling for empty search ID
func TestUnitGetObjectDescriptorsRelatedToSavedSearch_EmptySearchID(t *testing.T) {
	service := setupMockClient(t)

	result, err := service.GetObjectDescriptorsRelatedToSavedSearch(context.Background(), "", RelationshipEditors, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot be empty")
}

// TestUnitGetObjectDescriptorsRelatedToSavedSearch_EmptyRelationship tests error handling for empty relationship
func TestUnitGetObjectDescriptorsRelatedToSavedSearch_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	result, err := service.GetObjectDescriptorsRelatedToSavedSearch(context.Background(), testSavedSearchID, "", nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}
