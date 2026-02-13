package collections

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/vt_enterprise/collections/mocks"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupMockClient creates a client with httpmock enabled
func setupMockClient(t *testing.T) *Service {
	// Create test logger
	logger := zap.NewNop()

	// Create base URL for testing
	baseURL := "https://www.virustotal.com/api/v3"

	// Create HTTP client
	httpClient, err := client.NewClient("test-api-key",
		client.WithLogger(logger),
		client.WithBaseURL(baseURL),
	)
	require.NoError(t, err)

	// Activate httpmock
	httpmock.ActivateNonDefault(httpClient.GetHTTPClient().Client())

	// Setup cleanup
	t.Cleanup(func() {
		httpmock.DeactivateAndReset()
	})

	// Create collections service
	return NewService(httpClient)
}

// =============================================================================
// CreateCollection Tests
// =============================================================================

func TestUnitCreateCollection_Success_WithRelationships(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	req := &CreateCollectionRequest{
		Data: CreateCollectionData{
			Type: "collection",
			Attributes: CreateCollectionAttributes{
				Name:        "Test Collection",
				Description: "This is a test collection",
			},
			Relationships: &CollectionRelationships{
				Domains: &RelationshipData{
					Data: []RelationshipItem{
						{Type: "domain", ID: "virustotal.com"},
					},
				},
			},
		},
	}

	result, resp, err := service.CreateCollection(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, "collection", result.Data.Type)
	assert.Equal(t, "test-collection-123", result.Data.ID)
	assert.Equal(t, "Test Collection", result.Data.Attributes.Name)
	assert.Equal(t, "This is a test collection", result.Data.Attributes.Description)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitCreateCollection_Success_WithRawItems(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	req := &CreateCollectionRequest{
		Data: CreateCollectionData{
			Type: "collection",
			Attributes: CreateCollectionAttributes{
				Name: "Test Collection",
			},
			RawItems: "virustotal.com",
		},
	}

	result, resp, err := service.CreateCollection(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, "collection", result.Data.Type)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitCreateCollection_EmptyName(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	req := &CreateCollectionRequest{
		Data: CreateCollectionData{
			Type: "collection",
			Attributes: CreateCollectionAttributes{
				Name: "",
			},
			RawItems: "test",
		},
	}

	result, resp, err := service.CreateCollection(ctx, req)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection name cannot be empty")
}

func TestUnitCreateCollection_NilRequest(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()

	result, resp, err := service.CreateCollection(ctx, nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "create collection request cannot be nil")
}

func TestUnitCreateCollection_NoRelationshipsOrRawItems(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	req := &CreateCollectionRequest{
		Data: CreateCollectionData{
			Type: "collection",
			Attributes: CreateCollectionAttributes{
				Name: "Test",
			},
		},
	}

	result, resp, err := service.CreateCollection(ctx, req)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "either relationships or raw_items must be provided")
}

// =============================================================================
// GetCollection Tests
// =============================================================================

func TestUnitGetCollection_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.GetCollection(ctx, "test-collection-123")

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, "collection", result.Data.Type)
	assert.Equal(t, "test-collection-123", result.Data.ID)
	assert.Equal(t, "Test Collection", result.Data.Attributes.Name)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetCollection_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetCollection(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection ID cannot be empty")
}

// =============================================================================
// UpdateCollection Tests
// =============================================================================

func TestUnitUpdateCollection_Success_WithAttributes(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	req := &UpdateCollectionRequest{
		Data: UpdateCollectionData{
			Type: "collection",
			Attributes: &UpdateCollectionAttributes{
				Name:        "Updated Collection Name",
				Description: "Updated description",
			},
		},
	}

	result, resp, err := service.UpdateCollection(ctx, "test-collection-123", req)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, "Updated Collection Name", result.Data.Attributes.Name)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitUpdateCollection_Success_WithRawItems(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	req := &UpdateCollectionRequest{
		Data: UpdateCollectionData{
			Type:     "collection",
			RawItems: "new items",
		},
	}

	result, resp, err := service.UpdateCollection(ctx, "test-collection-123", req)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitUpdateCollection_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	req := &UpdateCollectionRequest{
		Data: UpdateCollectionData{
			Type:     "collection",
			RawItems: "test",
		},
	}

	result, resp, err := service.UpdateCollection(ctx, "", req)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection ID cannot be empty")
}

func TestUnitUpdateCollection_NilRequest(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()

	result, resp, err := service.UpdateCollection(ctx, "test-collection-123", nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "update collection request cannot be nil")
}

func TestUnitUpdateCollection_NoFieldsToUpdate(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	req := &UpdateCollectionRequest{
		Data: UpdateCollectionData{
			Type: "collection",
		},
	}

	result, resp, err := service.UpdateCollection(ctx, "test-collection-123", req)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "at least one field must be provided for update")
}

// =============================================================================
// DeleteCollection Tests
// =============================================================================

func TestUnitDeleteCollection_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.DeleteCollection(ctx, "test-collection-123")

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, "collection", result.Data.Type)
	assert.Equal(t, "test-collection-123", result.Data.ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitDeleteCollection_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.DeleteCollection(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection ID cannot be empty")
}

// =============================================================================
// GetCommentsOnCollection Tests
// =============================================================================

func TestUnitGetCommentsOnCollection_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.GetCommentsOnCollection(ctx, "test-collection-123", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Len(t, result.Data, 2)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.Equal(t, "This is a test comment", result.Data[0].Attributes.Text)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetCommentsOnCollection_Success_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit:  10,
		Cursor: "test-cursor",
	}

	result, resp, err := service.GetCommentsOnCollection(ctx, "test-collection-123", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetCommentsOnCollection_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetCommentsOnCollection(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection ID cannot be empty")
}

// =============================================================================
// AddCommentToCollection Tests
// =============================================================================

func TestUnitAddCommentToCollection_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.AddCommentToCollection(ctx, "test-collection-123", "New test comment")

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, "comment", result.Data.Type)
	assert.Equal(t, "New test comment", result.Data.Attributes.Text)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitAddCommentToCollection_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.AddCommentToCollection(ctx, "", "Test")

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection ID cannot be empty")
}

func TestUnitAddCommentToCollection_EmptyComment(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.AddCommentToCollection(ctx, "test-collection-123", "")

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "comment text cannot be empty")
}

// =============================================================================
// GetObjectsRelatedToCollection Tests
// =============================================================================

func TestUnitGetObjectsRelatedToCollection_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.GetObjectsRelatedToCollection(ctx, "test-collection-123", RelationshipDomains, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Len(t, result.Data, 2)
	assert.Equal(t, "domain", result.Data[0].Type)
	assert.Equal(t, "virustotal.com", result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToCollection_Success_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit:  20,
		Cursor: "test-cursor",
	}

	result, resp, err := service.GetObjectsRelatedToCollection(ctx, "test-collection-123", RelationshipDomains, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToCollection_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetObjectsRelatedToCollection(ctx, "", RelationshipDomains, nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection ID cannot be empty")
}

func TestUnitGetObjectsRelatedToCollection_InvalidRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetObjectsRelatedToCollection(ctx, "test-collection-123", "invalid", nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid relationship")
}

// =============================================================================
// GetObjectDescriptorsRelatedToCollection Tests
// =============================================================================

func TestUnitGetObjectDescriptorsRelatedToCollection_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.GetObjectDescriptorsRelatedToCollection(ctx, "test-collection-123", RelationshipDomains, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Len(t, result.Data, 2)
	assert.Equal(t, "domain", result.Data[0].Type)
	assert.Equal(t, "virustotal.com", result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectDescriptorsRelatedToCollection_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetObjectDescriptorsRelatedToCollection(ctx, "", RelationshipDomains, nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection ID cannot be empty")
}

func TestUnitGetObjectDescriptorsRelatedToCollection_InvalidRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetObjectDescriptorsRelatedToCollection(ctx, "test-collection-123", "invalid", nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid relationship")
}

// =============================================================================
// AddItemsToCollection Tests
// =============================================================================

func TestUnitAddItemsToCollection_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	req := &AddItemsRequest{
		Data: []RelationshipItem{
			{Type: "domain", ID: "example.com"},
		},
	}

	result, resp, err := service.AddItemsToCollection(ctx, "test-collection-123", RelationshipDomains, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, "collection", result.Data.Type)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitAddItemsToCollection_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	req := &AddItemsRequest{
		Data: []RelationshipItem{
			{Type: "domain", ID: "example.com"},
		},
	}

	result, resp, err := service.AddItemsToCollection(ctx, "", RelationshipDomains, req)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection ID cannot be empty")
}

func TestUnitAddItemsToCollection_NilRequest(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()

	result, resp, err := service.AddItemsToCollection(ctx, "test-collection-123", RelationshipDomains, nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "add items request cannot be nil")
}

// =============================================================================
// DeleteItemsFromCollection Tests
// =============================================================================

func TestUnitDeleteItemsFromCollection_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCollectionsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	req := &DeleteItemsRequest{
		Data: []RelationshipItem{
			{Type: "domain", ID: "example.com"},
		},
	}

	result, resp, err := service.DeleteItemsFromCollection(ctx, "test-collection-123", RelationshipDomains, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, "collection", result.Data.Type)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitDeleteItemsFromCollection_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	req := &DeleteItemsRequest{
		Data: []RelationshipItem{
			{Type: "domain", ID: "example.com"},
		},
	}

	result, resp, err := service.DeleteItemsFromCollection(ctx, "", RelationshipDomains, req)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "collection ID cannot be empty")
}

func TestUnitDeleteItemsFromCollection_NilRequest(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()

	result, resp, err := service.DeleteItemsFromCollection(ctx, "test-collection-123", RelationshipDomains, nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "delete items request cannot be nil")
}
