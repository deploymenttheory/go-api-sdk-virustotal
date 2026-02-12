package urls

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/urls/mocks"
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
	result, _, err := service.ScanURL(ctx, "https://www.example.com")

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
	result, _, err := service.ScanURL(ctx, "")

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
	result, _, err := service.GetURLReport(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20")

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
	result, _, err := service.GetURLReport(ctx, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "url", result.Data.Type)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetURLReport_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetURLReport(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetURLReport_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetURLReport(ctx, "invalid+id")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}

func TestUnitGetURLReport_PaddedBase64(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetURLReport(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20=")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "padding character '=' is not allowed")
}

func TestUnitGetURLReport_NotFound(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterErrorMocks()

	ctx := context.Background()
	result, _, err := service.GetURLReport(ctx, "aHR0cHM6Ly9ub3Rmb3VuZC50ZXN0")

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
	result, _, err := service.RescanURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "analysis", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitRescanURL_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.RescanURL(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitRescanURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.RescanURL(ctx, "invalid/id")

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
	result, _, err := service.GetCommentsOnURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", nil)

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
	result, _, err := service.GetCommentsOnURL(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetCommentsOnURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetCommentsOnURL(ctx, "invalid@id", nil)

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
	result, _, err := service.AddCommentToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "This is a test comment")

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
	result, _, err := service.AddCommentToURL(ctx, "", "Test comment")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitAddCommentToURL_EmptyComment(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddCommentToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment text is required")
}

func TestUnitAddCommentToURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddCommentToURL(ctx, "invalid!id", "Test comment")

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
	result, _, err := service.GetObjectsRelatedToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "comments", nil)

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
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", "comments", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetObjectsRelatedToURL_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

func TestUnitGetObjectsRelatedToURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "invalid#id", "comments", nil)

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
	result, _, err := service.GetObjectDescriptorsRelatedToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "comments", nil)

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
	result, _, err := service.GetObjectDescriptorsRelatedToURL(ctx, "", "comments", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetObjectDescriptorsRelatedToURL_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectDescriptorsRelatedToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

func TestUnitGetObjectDescriptorsRelatedToURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectDescriptorsRelatedToURL(ctx, "invalid$id", "comments", nil)

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
	result, _, err := service.GetVotesOnURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", nil)

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
	result, _, err := service.GetVotesOnURL(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitGetVotesOnURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetVotesOnURL(ctx, "invalid%id", nil)

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
	result, _, err := service.AddVoteToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "harmless")

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
	result, _, err := service.AddVoteToURL(ctx, "", "harmless")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

func TestUnitAddVoteToURL_EmptyVerdict(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "verdict is required")
}

func TestUnitAddVoteToURL_InvalidVerdict(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToURL(ctx, "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20", "invalid")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "verdict must be 'harmless' or 'malicious'")
}

func TestUnitAddVoteToURL_InvalidURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToURL(ctx, "invalid&id", "harmless")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID must be either a SHA-256 hash")
}

const testURLID = "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20"

// =============================================================================
// Analyses Relationship Tests
// =============================================================================

func TestUnitGetURLAnalyses_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipAnalyses, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "analysis", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLAnalyses_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipAnalyses, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Collections Relationship Tests
// =============================================================================

func TestUnitGetURLCollections_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipCollections, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "collection", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLCollections_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipCollections, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Comments Relationship Tests
// =============================================================================

func TestUnitGetURLComments_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipComments, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLComments_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipComments, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Communicating Files Relationship Tests
// =============================================================================

func TestUnitGetURLCommunicatingFiles_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipCommunicatingFiles, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLCommunicatingFiles_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipCommunicatingFiles, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Contacted Domains Relationship Tests
// =============================================================================

func TestUnitGetURLContactedDomains_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipContactedDomains, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "domain", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLContactedDomains_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipContactedDomains, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Contacted IPs Relationship Tests
// =============================================================================

func TestUnitGetURLContactedIPs_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipContactedIPs, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "ip_address", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLContactedIPs_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipContactedIPs, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Downloaded Files Relationship Tests
// =============================================================================

func TestUnitGetURLDownloadedFiles_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipDownloadedFiles, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLDownloadedFiles_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipDownloadedFiles, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Embedded JS Files Relationship Tests
// =============================================================================

func TestUnitGetURLEmbeddedJSFiles_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipEmbeddedJSFiles, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	// Verify context attributes
	if result.Data[0].ContextAttributes != nil {
		assert.Contains(t, result.Data[0].ContextAttributes, "url")
	}
}

func TestUnitGetURLEmbeddedJSFiles_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipEmbeddedJSFiles, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Graphs Relationship Tests
// =============================================================================

func TestUnitGetURLGraphs_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipGraphs, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "graph", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLGraphs_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipGraphs, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Last Serving IP Address Relationship Tests
// =============================================================================

func TestUnitGetURLLastServingIPAddress_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipLastServingIPAddress, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "ip_address", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLLastServingIPAddress_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipLastServingIPAddress, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Network Location Relationship Tests
// =============================================================================

func TestUnitGetURLNetworkLocation_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipNetworkLocation, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.NotEmpty(t, result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLNetworkLocation_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipNetworkLocation, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Redirecting URLs Relationship Tests
// =============================================================================

func TestUnitGetURLRedirectingURLs_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRedirectingURLs, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "url", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLRedirectingURLs_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRedirectingURLs, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Redirects To Relationship Tests
// =============================================================================

func TestUnitGetURLRedirectsTo_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRedirectsTo, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "url", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLRedirectsTo_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRedirectsTo, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Referrer Files Relationship Tests
// =============================================================================

func TestUnitGetURLReferrerFiles_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipReferrerFiles, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLReferrerFiles_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipReferrerFiles, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Referrer URLs Relationship Tests
// =============================================================================

func TestUnitGetURLReferrerURLs_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipReferrerURLs, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "url", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	// Verify context attributes
	if result.Data[0].ContextAttributes != nil {
		assert.Contains(t, result.Data[0].ContextAttributes, "url")
	}
}

func TestUnitGetURLReferrerURLs_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipReferrerURLs, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Related Comments Relationship Tests
// =============================================================================

func TestUnitGetURLRelatedComments_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRelatedComments, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	// Verify context attributes
	if result.Data[0].ContextAttributes != nil {
		assert.Contains(t, result.Data[0].ContextAttributes, "posted_in")
	}
}

func TestUnitGetURLRelatedComments_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRelatedComments, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Related References Relationship Tests
// =============================================================================

func TestUnitGetURLRelatedReferences_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRelatedReferences, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "reference", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	// Verify context attributes
	if result.Data[0].ContextAttributes != nil {
		assert.Contains(t, result.Data[0].ContextAttributes, "related_from")
	}
}

func TestUnitGetURLRelatedReferences_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRelatedReferences, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Related Threat Actors Relationship Tests
// =============================================================================

func TestUnitGetURLRelatedThreatActors_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRelatedThreatActors, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "threat_actor", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	// Verify context attributes
	if result.Data[0].ContextAttributes != nil {
		assert.Contains(t, result.Data[0].ContextAttributes, "related_from")
	}
}

func TestUnitGetURLRelatedThreatActors_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRelatedThreatActors, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Submissions Relationship Tests
// =============================================================================

func TestUnitGetURLSubmissions_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipSubmissions, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "submission", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLSubmissions_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipSubmissions, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// User Votes Relationship Tests
// =============================================================================

func TestUnitGetURLUserVotes_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipUserVotes, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "vote", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLUserVotes_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipUserVotes, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// Votes Relationship Tests
// =============================================================================

func TestUnitGetURLVotesRelationship_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipVotes, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "vote", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLVotesRelationship_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipVotes, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}

// =============================================================================
// URLs Related By Tracker ID Relationship Tests
// =============================================================================

func TestUnitGetURLsRelatedByTrackerID_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipURLsRelatedByTrackerID, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "url", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	// Verify context attributes
	if result.Data[0].ContextAttributes != nil {
		assert.Contains(t, result.Data[0].ContextAttributes, "url")
	}
}

func TestUnitGetURLsRelatedByTrackerID_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipURLsRelatedByTrackerID, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}
