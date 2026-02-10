package urls

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/urls/mocks"
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

	// Create URLs service
	return NewService(httpClient)
}

// =============================================================================
// ScanURL Tests
// =============================================================================

func TestUnitScanURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.ScanURL(ctx, "https://www.example.com")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "analysis", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
	assert.Contains(t, result.Data.ID, "u-")

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitScanURL_EmptyURL(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.ScanURL(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL is required")
}

// =============================================================================
// GetURLReport Tests
// =============================================================================

func TestUnitGetURLReport_Success_Base64ID(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetURLReport(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "url", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)

	// Verify URL information
	attrs := result.Data.Attributes
	assert.Equal(t, "https://www.example.com", attrs.URL)
	assert.Equal(t, "Example Domain", attrs.Title)
	assert.Equal(t, 1450, attrs.Reputation)
	assert.Equal(t, 78, attrs.LastAnalysisStats.Harmless)
	assert.Equal(t, 0, attrs.LastAnalysisStats.Malicious)
	assert.Equal(t, 0, attrs.LastAnalysisStats.Suspicious)
	assert.Equal(t, 10, attrs.LastAnalysisStats.Undetected)
	assert.Equal(t, 200, attrs.LastHTTPResponseCode)

	// Verify votes
	assert.Equal(t, 1400, attrs.TotalVotes.Harmless)
	assert.Equal(t, 5, attrs.TotalVotes.Malicious)

	// Verify categories
	assert.Contains(t, attrs.Categories, "Alexa")
	assert.Equal(t, "search engines and portals", attrs.Categories["Alexa"])

	// Verify tags
	assert.Contains(t, attrs.Tags, "popular")

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetURLReport_Success_SHA256ID(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetURLReport(ctx, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "url", result.Data.Type)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetURLReport_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetURLReport(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetURLReport_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetURLReport(ctx, "invalid+id")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}

func TestUnitGetURLReport_PaddedBase64(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetURLReport(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20=")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "padding character '=' is not allowed")
}

func TestUnitGetURLReport_NotFound(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterErrorMocks()

	ctx := context.Background()
	result, err := service.GetURLReport(ctx, "aHR0cHM6Ly9ub3Rmb3VuZC50ZXN0")

	require.Error(t, err)
	require.Nil(t, result)
}

// =============================================================================
// RescanURL Tests
// =============================================================================

func TestUnitRescanURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.RescanURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "analysis", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitRescanURL_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.RescanURL(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitRescanURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.RescanURL(ctx, "invalid/id")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}

// =============================================================================
// GetCommentsOnURL Tests
// =============================================================================

func TestUnitGetCommentsOnURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetCommentsOnURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetCommentsOnURL_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetCommentsOnURL(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetCommentsOnURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetCommentsOnURL(ctx, "invalid@id", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}

// =============================================================================
// AddCommentToURL Tests
// =============================================================================

func TestUnitAddCommentToURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.AddCommentToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "This is a test comment")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "comment", result.Data.Type)
	assert.Equal(t, "This is a test comment", result.Data.Attributes.Text)
	assert.Equal(t, "<p>This is a test comment</p>", result.Data.Attributes.HTML)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitAddCommentToURL_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddCommentToURL(ctx, "", "Test comment")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitAddCommentToURL_EmptyComment(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddCommentToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment text is required")
}

func TestUnitAddCommentToURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddCommentToURL(ctx, "invalid!id", "Test comment")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}

// =============================================================================
// GetObjectsRelatedToURL Tests
// =============================================================================

func TestUnitGetObjectsRelatedToURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "comments", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetObjectsRelatedToURL_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", "comments", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetObjectsRelatedToURL_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

func TestUnitGetObjectsRelatedToURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "invalid#id", "comments", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}

// =============================================================================
// GetObjectDescriptorsRelatedToURL Tests
// =============================================================================

func TestUnitGetObjectDescriptorsRelatedToURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "comments", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetObjectDescriptorsRelatedToURL_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToURL(ctx, "", "comments", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetObjectDescriptorsRelatedToURL_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

func TestUnitGetObjectDescriptorsRelatedToURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToURL(ctx, "invalid$id", "comments", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}

// =============================================================================
// GetVotesOnURL Tests
// =============================================================================

func TestUnitGetVotesOnURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetVotesOnURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "vote", result.Data[0].Type)
	assert.Contains(t, []string{"harmless", "malicious"}, result.Data[0].Attributes.Verdict)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetVotesOnURL_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetVotesOnURL(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetVotesOnURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetVotesOnURL(ctx, "invalid%id", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}

// =============================================================================
// AddVoteToURL Tests
// =============================================================================

func TestUnitAddVoteToURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.AddVoteToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "harmless")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "vote", result.Data.Type)
	assert.Equal(t, "harmless", result.Data.Attributes.Verdict)
	assert.Equal(t, 1, result.Data.Attributes.Value)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitAddVoteToURL_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddVoteToURL(ctx, "", "harmless")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitAddVoteToURL_EmptyVerdict(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddVoteToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "verdict is required")
}

func TestUnitAddVoteToURL_InvalidVerdict(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddVoteToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "invalid")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "verdict must be 'harmless' or 'malicious'")
}

func TestUnitAddVoteToURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddVoteToURL(ctx, "invalid&id", "harmless")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}
