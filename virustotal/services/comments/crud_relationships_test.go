package comments

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/comments/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCommentID = "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345"

// =============================================================================
// Author Relationship Tests
// =============================================================================

func TestUnitGetCommentAuthor_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToComment(ctx, testCommentID, RelationshipAuthor, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "user", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetCommentAuthor_EmptyCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToComment(ctx, "", RelationshipAuthor, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID cannot be empty")
}

func TestUnitGetCommentAuthor_InvalidCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToComment(ctx, "invalid-id", RelationshipAuthor, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID must be in format")
}

// =============================================================================
// Author Relationship Descriptor Tests
// =============================================================================

func TestUnitGetCommentAuthorDescriptor_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToComment(ctx, testCommentID, RelationshipAuthor, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "user", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetCommentAuthorDescriptor_EmptyCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToComment(ctx, "", RelationshipAuthor, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID cannot be empty")
}

func TestUnitGetCommentAuthorDescriptor_InvalidCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToComment(ctx, "invalid-id", RelationshipAuthor, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID must be in format")
}
