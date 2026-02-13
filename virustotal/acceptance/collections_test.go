package acceptance

import (
	"fmt"
	"testing"
	"time"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/vt_enterprise/collections"
	"github.com/stretchr/testify/assert"
)

// Global variable to store the created collection ID for chaining tests
var createdCollectionID string

// =============================================================================
// CreateCollection Tests
// =============================================================================

// TestAcceptance_Collections_CreateCollection tests creating a new collection
func TestAcceptance_Collections_CreateCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Use timestamp to make collection name unique
		timestamp := time.Now().Unix()
		collectionName := fmt.Sprintf("Test Collection %d", timestamp)

		LogTestStage(t, "📦 Create Collection", "Creating collection: %s", collectionName)

		req := &collections.CreateCollectionRequest{
			Data: collections.CreateCollectionData{
				Type: "collection",
				Attributes: collections.CreateCollectionAttributes{
					Name:        collectionName,
					Description: "Acceptance test collection created by SDK",
				},
				Relationships: &collections.CollectionRelationships{
					Domains: &collections.RelationshipData{
						Data: []collections.RelationshipItem{
							{Type: "domain", ID: "virustotal.com"},
						},
					},
				},
			},
		}

		result, resp, err := service.CreateCollection(ctx, req)
		AssertNoError(t, err, "CreateCollection should not return an error")
		AssertNotNil(t, result, "CreateCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.Equal(t, "collection", result.Data.Type, "Result type should be 'collection'")
		assert.NotEmpty(t, result.Data.ID, "Collection ID should not be empty")
		assert.Equal(t, collectionName, result.Data.Attributes.Name, "Collection name should match")
		assert.NotZero(t, result.Data.Attributes.CreationDate, "Creation date should be set")

		// Store collection ID for subsequent tests
		createdCollectionID = result.Data.ID

		LogTestSuccess(t, "Collection created with ID: %s", result.Data.ID)
		LogTestSuccess(t, "Collection name: %s", result.Data.Attributes.Name)
	})
}

// TestAcceptance_Collections_CreateCollection_WithRawItems tests creating a collection with raw items
func TestAcceptance_Collections_CreateCollection_WithRawItems(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		timestamp := time.Now().Unix()
		collectionName := fmt.Sprintf("Test Collection Raw %d", timestamp)

		LogTestStage(t, "📦 Create Collection (Raw Items)", "Creating collection with raw items")

		req := &collections.CreateCollectionRequest{
			Data: collections.CreateCollectionData{
				Type: "collection",
				Attributes: collections.CreateCollectionAttributes{
					Name:        collectionName,
					Description: "Test collection with raw items",
				},
				RawItems: "virustotal.com google.com",
			},
		}

		result, resp, err := service.CreateCollection(ctx, req)
		AssertNoError(t, err, "CreateCollection should not return an error")
		AssertNotNil(t, result, "CreateCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.Equal(t, "collection", result.Data.Type, "Result type should be 'collection'")
		assert.NotEmpty(t, result.Data.ID, "Collection ID should not be empty")

		LogTestSuccess(t, "Collection created with raw items, ID: %s", result.Data.ID)

		// Clean up - delete the collection
		_, _, deleteErr := service.DeleteCollection(ctx, result.Data.ID)
		if deleteErr != nil {
			LogTestWarning(t, "Failed to clean up collection: %v", deleteErr)
		}
	})
}

// TestAcceptance_Collections_CreateCollection_EmptyName tests validation for empty name
func TestAcceptance_Collections_CreateCollection_EmptyName(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := collections.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing CreateCollection with empty name")

	req := &collections.CreateCollectionRequest{
		Data: collections.CreateCollectionData{
			Type: "collection",
			Attributes: collections.CreateCollectionAttributes{
				Name: "",
			},
			RawItems: "test",
		},
	}

	result, _, err := service.CreateCollection(ctx, req)

	assert.Error(t, err, "CreateCollection should return an error for empty name")
	assert.Nil(t, result, "CreateCollection result should be nil for empty name")
	assert.Contains(t, err.Error(), "collection name cannot be empty", "Error message should indicate empty name")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}

// =============================================================================
// GetCollection Tests
// =============================================================================

// TestAcceptance_Collections_GetCollection tests retrieving a collection
func TestAcceptance_Collections_GetCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID from previous test
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "📖 Get Collection", "Retrieving collection: %s", createdCollectionID)

		result, resp, err := service.GetCollection(ctx, createdCollectionID)
		AssertNoError(t, err, "GetCollection should not return an error")
		AssertNotNil(t, result, "GetCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.Equal(t, "collection", result.Data.Type, "Result type should be 'collection'")
		assert.Equal(t, createdCollectionID, result.Data.ID, "Collection ID should match")
		assert.NotEmpty(t, result.Data.Attributes.Name, "Collection name should not be empty")

		LogTestSuccess(t, "Collection retrieved successfully")
		LogTestSuccess(t, "Collection name: %s", result.Data.Attributes.Name)
		LogTestSuccess(t, "Created: %d, Modified: %d", result.Data.Attributes.CreationDate, result.Data.Attributes.ModificationDate)
	})
}

// TestAcceptance_Collections_GetCollection_EmptyID tests validation for empty ID
func TestAcceptance_Collections_GetCollection_EmptyID(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := collections.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing GetCollection with empty ID")

	result, _, err := service.GetCollection(ctx, "")

	assert.Error(t, err, "GetCollection should return an error for empty ID")
	assert.Nil(t, result, "GetCollection result should be nil for empty ID")
	assert.Contains(t, err.Error(), "collection ID cannot be empty", "Error message should indicate empty ID")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}

// =============================================================================
// UpdateCollection Tests
// =============================================================================

// TestAcceptance_Collections_UpdateCollection tests updating a collection
func TestAcceptance_Collections_UpdateCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		timestamp := time.Now().Unix()
		updatedName := fmt.Sprintf("Updated Collection %d", timestamp)

		LogTestStage(t, "✏️  Update Collection", "Updating collection: %s", createdCollectionID)

		req := &collections.UpdateCollectionRequest{
			Data: collections.UpdateCollectionData{
				Type: "collection",
				Attributes: &collections.UpdateCollectionAttributes{
					Name:        updatedName,
					Description: "Updated by acceptance test",
				},
			},
		}

		result, resp, err := service.UpdateCollection(ctx, createdCollectionID, req)
		AssertNoError(t, err, "UpdateCollection should not return an error")
		AssertNotNil(t, result, "UpdateCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.Equal(t, "collection", result.Data.Type, "Result type should be 'collection'")
		assert.Equal(t, createdCollectionID, result.Data.ID, "Collection ID should match")
		assert.Equal(t, updatedName, result.Data.Attributes.Name, "Collection name should be updated")

		LogTestSuccess(t, "Collection updated successfully")
		LogTestSuccess(t, "New name: %s", result.Data.Attributes.Name)
	})
}

// TestAcceptance_Collections_UpdateCollection_WithRawItems tests updating with raw items
func TestAcceptance_Collections_UpdateCollection_WithRawItems(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "✏️  Update Collection (Raw Items)", "Adding items via raw text")

		req := &collections.UpdateCollectionRequest{
			Data: collections.UpdateCollectionData{
				Type:     "collection",
				RawItems: "example.com 1.1.1.1",
			},
		}

		result, resp, err := service.UpdateCollection(ctx, createdCollectionID, req)
		AssertNoError(t, err, "UpdateCollection should not return an error")
		AssertNotNil(t, result, "UpdateCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		LogTestSuccess(t, "Collection updated with raw items")
	})
}

// =============================================================================
// AddCommentToCollection Tests
// =============================================================================

// TestAcceptance_Collections_AddCommentToCollection tests adding a comment
func TestAcceptance_Collections_AddCommentToCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "💬 Add Comment", "Adding comment to collection: %s", createdCollectionID)

		commentText := "Test comment added by SDK acceptance test #test #automation"

		result, resp, err := service.AddCommentToCollection(ctx, createdCollectionID, commentText)
		AssertNoError(t, err, "AddCommentToCollection should not return an error")
		AssertNotNil(t, result, "AddCommentToCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.Equal(t, "comment", result.Data.Type, "Result type should be 'comment'")
		assert.NotEmpty(t, result.Data.ID, "Comment ID should not be empty")
		assert.NotZero(t, result.Data.Attributes.Date, "Comment date should be set")
		
		// Verify tags were extracted
		if len(result.Data.Attributes.Tags) > 0 {
			LogTestSuccess(t, "Tags extracted: %v", result.Data.Attributes.Tags)
		}

		LogTestSuccess(t, "Comment added with ID: %s", result.Data.ID)
	})
}

// TestAcceptance_Collections_AddCommentToCollection_EmptyComment tests validation for empty comment
func TestAcceptance_Collections_AddCommentToCollection_EmptyComment(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := collections.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing AddCommentToCollection with empty comment")

	result, _, err := service.AddCommentToCollection(ctx, "test-id", "")

	assert.Error(t, err, "AddCommentToCollection should return an error for empty comment")
	assert.Nil(t, result, "AddCommentToCollection result should be nil for empty comment")
	assert.Contains(t, err.Error(), "comment text cannot be empty", "Error message should indicate empty comment")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}

// =============================================================================
// GetCommentsOnCollection Tests
// =============================================================================

// TestAcceptance_Collections_GetCommentsOnCollection tests retrieving comments
func TestAcceptance_Collections_GetCommentsOnCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "💬 Get Comments", "Retrieving comments for collection: %s", createdCollectionID)

		result, resp, err := service.GetCommentsOnCollection(ctx, createdCollectionID, nil)
		AssertNoError(t, err, "GetCommentsOnCollection should not return an error")
		AssertNotNil(t, result, "GetCommentsOnCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Comments data should not be nil")

		if len(result.Data) > 0 {
			LogTestSuccess(t, "Found %d comment(s)", len(result.Data))
			firstComment := result.Data[0]
			assert.Equal(t, "comment", firstComment.Type, "Comment type should be 'comment'")
			assert.NotEmpty(t, firstComment.ID, "Comment ID should not be empty")
			LogTestSuccess(t, "First comment text: %s", firstComment.Attributes.Text)
		} else {
			LogTestWarning(t, "No comments found for collection")
		}
	})
}

// TestAcceptance_Collections_GetCommentsOnCollection_WithOptions tests retrieving comments with options
func TestAcceptance_Collections_GetCommentsOnCollection_WithOptions(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "💬 Get Comments (Options)", "Retrieving comments with limit")

		opts := &collections.GetRelatedObjectsOptions{
			Limit: 5,
		}

		result, resp, err := service.GetCommentsOnCollection(ctx, createdCollectionID, opts)
		AssertNoError(t, err, "GetCommentsOnCollection should not return an error")
		AssertNotNil(t, result, "GetCommentsOnCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate limit is respected
		if len(result.Data) > 0 {
			assert.LessOrEqual(t, len(result.Data), 5, "Should return at most 5 comments")
			LogTestSuccess(t, "Found %d comment(s) with limit of 5", len(result.Data))
		}
	})
}

// =============================================================================
// GetObjectsRelatedToCollection Tests
// =============================================================================

// TestAcceptance_Collections_GetObjectsRelatedToCollection tests retrieving related objects
func TestAcceptance_Collections_GetObjectsRelatedToCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "🔗 Get Related Objects", "Retrieving domains from collection: %s", createdCollectionID)

		result, resp, err := service.GetObjectsRelatedToCollection(ctx, createdCollectionID, collections.RelationshipDomains, nil)
		AssertNoError(t, err, "GetObjectsRelatedToCollection should not return an error")
		AssertNotNil(t, result, "GetObjectsRelatedToCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Related objects data should not be nil")

		if len(result.Data) > 0 {
			LogTestSuccess(t, "Found %d related domain(s)", len(result.Data))
			firstDomain := result.Data[0]
			assert.Equal(t, "domain", firstDomain.Type, "Object type should be 'domain'")
			assert.NotEmpty(t, firstDomain.ID, "Domain ID should not be empty")
			LogTestSuccess(t, "First domain: %s", firstDomain.ID)
		} else {
			LogTestWarning(t, "No related domains found")
		}
	})
}

// TestAcceptance_Collections_GetObjectsRelatedToCollection_InvalidRelationship tests invalid relationship
func TestAcceptance_Collections_GetObjectsRelatedToCollection_InvalidRelationship(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := collections.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing GetObjectsRelatedToCollection with invalid relationship")

	result, _, err := service.GetObjectsRelatedToCollection(ctx, "test-id", "invalid_relationship", nil)

	assert.Error(t, err, "GetObjectsRelatedToCollection should return an error for invalid relationship")
	assert.Nil(t, result, "GetObjectsRelatedToCollection result should be nil for invalid relationship")
	assert.Contains(t, err.Error(), "invalid relationship", "Error message should indicate invalid relationship")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}

// =============================================================================
// GetObjectDescriptorsRelatedToCollection Tests
// =============================================================================

// TestAcceptance_Collections_GetObjectDescriptorsRelatedToCollection tests retrieving object descriptors
func TestAcceptance_Collections_GetObjectDescriptorsRelatedToCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "🔗 Get Object Descriptors", "Retrieving domain descriptors from collection: %s", createdCollectionID)

		result, resp, err := service.GetObjectDescriptorsRelatedToCollection(ctx, createdCollectionID, collections.RelationshipDomains, nil)
		AssertNoError(t, err, "GetObjectDescriptorsRelatedToCollection should not return an error")
		AssertNotNil(t, result, "GetObjectDescriptorsRelatedToCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Object descriptors data should not be nil")

		if len(result.Data) > 0 {
			LogTestSuccess(t, "Found %d object descriptor(s)", len(result.Data))
			firstDescriptor := result.Data[0]
			assert.Equal(t, "domain", firstDescriptor.Type, "Descriptor type should be 'domain'")
			assert.NotEmpty(t, firstDescriptor.ID, "Descriptor ID should not be empty")
			LogTestSuccess(t, "First descriptor: %s", firstDescriptor.ID)
		} else {
			LogTestWarning(t, "No object descriptors found")
		}
	})
}

// =============================================================================
// AddItemsToCollection Tests
// =============================================================================

// TestAcceptance_Collections_AddItemsToCollection tests adding items to a collection
func TestAcceptance_Collections_AddItemsToCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "➕ Add Items", "Adding domains to collection: %s", createdCollectionID)

		req := &collections.AddItemsRequest{
			Data: []collections.RelationshipItem{
				{Type: "domain", ID: "example.com"},
				{Type: "domain", ID: "test.com"},
			},
		}

		result, resp, err := service.AddItemsToCollection(ctx, createdCollectionID, collections.RelationshipDomains, req)
		AssertNoError(t, err, "AddItemsToCollection should not return an error")
		AssertNotNil(t, result, "AddItemsToCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.Equal(t, "collection", result.Data.Type, "Result type should be 'collection'")
		assert.Equal(t, createdCollectionID, result.Data.ID, "Collection ID should match")

		LogTestSuccess(t, "Items added successfully to collection")
	})
}

// TestAcceptance_Collections_AddItemsToCollection_WithURLs tests adding URLs
func TestAcceptance_Collections_AddItemsToCollection_WithURLs(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "➕ Add URLs", "Adding URLs to collection using URL field")

		req := &collections.AddItemsRequest{
			Data: []collections.RelationshipItem{
				{Type: "url", URL: "https://www.example.com"},
				{Type: "url", URL: "https://www.test.com"},
			},
		}

		result, resp, err := service.AddItemsToCollection(ctx, createdCollectionID, collections.RelationshipURLs, req)
		AssertNoError(t, err, "AddItemsToCollection should not return an error")
		AssertNotNil(t, result, "AddItemsToCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		LogTestSuccess(t, "URLs added successfully to collection")
	})
}

// TestAcceptance_Collections_AddItemsToCollection_EmptyItems tests validation for empty items
func TestAcceptance_Collections_AddItemsToCollection_EmptyItems(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := collections.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing AddItemsToCollection with empty items")

	req := &collections.AddItemsRequest{
		Data: []collections.RelationshipItem{},
	}

	result, _, err := service.AddItemsToCollection(ctx, "test-id", collections.RelationshipDomains, req)

	assert.Error(t, err, "AddItemsToCollection should return an error for empty items")
	assert.Nil(t, result, "AddItemsToCollection result should be nil for empty items")
	assert.Contains(t, err.Error(), "items list cannot be empty", "Error message should indicate empty items")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}

// =============================================================================
// DeleteItemsFromCollection Tests
// =============================================================================

// TestAcceptance_Collections_DeleteItemsFromCollection tests deleting items from a collection
func TestAcceptance_Collections_DeleteItemsFromCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "➖ Delete Items", "Removing domains from collection: %s", createdCollectionID)

		req := &collections.DeleteItemsRequest{
			Data: []collections.RelationshipItem{
				{Type: "domain", ID: "example.com"},
			},
		}

		result, resp, err := service.DeleteItemsFromCollection(ctx, createdCollectionID, collections.RelationshipDomains, req)
		AssertNoError(t, err, "DeleteItemsFromCollection should not return an error")
		AssertNotNil(t, result, "DeleteItemsFromCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.Equal(t, "collection", result.Data.Type, "Result type should be 'collection'")
		assert.Equal(t, createdCollectionID, result.Data.ID, "Collection ID should match")

		LogTestSuccess(t, "Items deleted successfully from collection")
	})
}

// =============================================================================
// DeleteCollection Tests (Cleanup)
// =============================================================================

// TestAcceptance_Collections_DeleteCollection tests deleting a collection
// This test runs last to clean up the test collection
func TestAcceptance_Collections_DeleteCollection(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := collections.NewService(Client)

		// Ensure we have a collection ID
		if createdCollectionID == "" {
			t.Skip("No collection ID available - CreateCollection test must run first")
		}

		LogTestStage(t, "🗑️  Delete Collection", "Deleting collection: %s", createdCollectionID)

		result, resp, err := service.DeleteCollection(ctx, createdCollectionID)
		AssertNoError(t, err, "DeleteCollection should not return an error")
		AssertNotNil(t, result, "DeleteCollection result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.Equal(t, "collection", result.Data.Type, "Result type should be 'collection'")
		assert.Equal(t, createdCollectionID, result.Data.ID, "Collection ID should match")

		LogTestSuccess(t, "Collection deleted successfully")

		// Clear the collection ID
		createdCollectionID = ""
	})
}

// TestAcceptance_Collections_DeleteCollection_EmptyID tests validation for empty ID
func TestAcceptance_Collections_DeleteCollection_EmptyID(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := collections.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing DeleteCollection with empty ID")

	result, _, err := service.DeleteCollection(ctx, "")

	assert.Error(t, err, "DeleteCollection should return an error for empty ID")
	assert.Nil(t, result, "DeleteCollection result should be nil for empty ID")
	assert.Contains(t, err.Error(), "collection ID cannot be empty", "Error message should indicate empty ID")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}
