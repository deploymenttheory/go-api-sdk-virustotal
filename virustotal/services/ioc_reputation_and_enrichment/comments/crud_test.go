package comments

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/comments/mocks"
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

	// Create comments service
	return NewService(httpClient)
}

// =============================================================================
// GetLatestComments Tests
// =============================================================================

func TestUnitGetLatestComments_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.GetLatestComments(ctx, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetLatestComments_WithFilter(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	opts := &GetCommentsOptions{
		Filter: "tag:malware",
		Limit:  10,
	}
	result, _, err := service.GetLatestComments(ctx, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

// =============================================================================
// GetComment Tests
// =============================================================================

func TestUnitGetComment_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.GetComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "comment", result.Data.Type)
	assert.Equal(t, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", result.Data.ID)

	// Verify comment attributes
	attrs := result.Data.Attributes
	assert.NotEmpty(t, attrs.Text)
	assert.Equal(t, "This URL looks suspicious #malware", attrs.Text)
	assert.Contains(t, attrs.Tags, "malware")
	assert.Equal(t, 5, attrs.Votes.Positive)
	assert.Equal(t, 1, attrs.Votes.Negative)
	assert.Equal(t, 0, attrs.Votes.Abuse)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetComment_EmptyCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetComment(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID cannot be empty")
}

func TestUnitGetComment_InvalidCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetComment(ctx, "invalid-id")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID must be in format")
}

func TestUnitGetComment_InvalidPrefix(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetComment(ctx, "x-example.com-abc123")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID must be in format")
}

func TestUnitGetComment_NotFound(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterErrorMocks()

	ctx := context.Background()
	result, _, err := service.GetComment(ctx, "d-notfound.test-abc123")

	require.Error(t, err)
	require.Nil(t, result)
}

// =============================================================================
// DeleteComment Tests
// =============================================================================

func TestUnitDeleteComment_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	_, err := service.DeleteComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345")

	require.NoError(t, err)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitDeleteComment_EmptyCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	_, err := service.DeleteComment(ctx, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "comment ID cannot be empty")
}

func TestUnitDeleteComment_InvalidCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	_, err := service.DeleteComment(ctx, "invalid@id")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "comment ID must be in format")
}

// =============================================================================
// GetObjectsRelatedToComment Tests
// =============================================================================

func TestUnitGetObjectsRelatedToComment_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", "author", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetObjectsRelatedToComment_EmptyCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToComment(ctx, "", "author", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID cannot be empty")
}

func TestUnitGetObjectsRelatedToComment_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

func TestUnitGetObjectsRelatedToComment_InvalidCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToComment(ctx, "invalid#id", "author", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID must be in format")
}

// =============================================================================
// GetObjectDescriptorsRelatedToComment Tests
// =============================================================================

func TestUnitGetObjectDescriptorsRelatedToComment_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectDescriptorsRelatedToComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", "author", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "user", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetObjectDescriptorsRelatedToComment_EmptyCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectDescriptorsRelatedToComment(ctx, "", "author", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID cannot be empty")
}

func TestUnitGetObjectDescriptorsRelatedToComment_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectDescriptorsRelatedToComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

func TestUnitGetObjectDescriptorsRelatedToComment_InvalidCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectDescriptorsRelatedToComment(ctx, "invalid$id", "author", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID must be in format")
}

// =============================================================================
// AddVoteToComment Tests
// =============================================================================

func TestUnitAddVoteToComment_Success_Positive(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.AddVoteToComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", 1, 0, 0)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.Data.Positive)
	assert.Equal(t, 0, result.Data.Negative)
	assert.Equal(t, 0, result.Data.Abuse)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitAddVoteToComment_Success_Negative(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.AddVoteToComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", 0, 1, 0)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitAddVoteToComment_Success_Abuse(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.AddVoteToComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", 0, 0, 1)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitAddVoteToComment_EmptyCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToComment(ctx, "", 1, 0, 0)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID cannot be empty")
}

func TestUnitAddVoteToComment_InvalidCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToComment(ctx, "invalid&id", 1, 0, 0)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID must be in format")
}

func TestUnitAddVoteToComment_NegativeValues(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", -1, 0, 0)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "vote values cannot be negative")
}

func TestUnitAddVoteToComment_AllNegativeValues(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToComment(ctx, "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345", -1, -1, -1)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "vote values cannot be negative")
}

const testCommentID = "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345"

// =============================================================================
// Author Relationship Tests
// =============================================================================

func TestUnitGetCommentAuthor_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCommentsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToComment(ctx, testCommentID, RelationshipAuthor, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "user", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetCommentAuthor_EmptyCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToComment(ctx, "", RelationshipAuthor, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID cannot be empty")
}

func TestUnitGetCommentAuthor_InvalidCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToComment(ctx, "invalid-id", RelationshipAuthor, nil)

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
	result, _, err := service.GetObjectDescriptorsRelatedToComment(ctx, testCommentID, RelationshipAuthor, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "user", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetCommentAuthorDescriptor_EmptyCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectDescriptorsRelatedToComment(ctx, "", RelationshipAuthor, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID cannot be empty")
}

func TestUnitGetCommentAuthorDescriptor_InvalidCommentID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectDescriptorsRelatedToComment(ctx, "invalid-id", RelationshipAuthor, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment ID must be in format")
}
