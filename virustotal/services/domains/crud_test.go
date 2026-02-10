package domains

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/domains/mocks"
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

	// Create domains service
	return NewService(httpClient)
}

// =============================================================================
// GetDomainReport Tests
// =============================================================================

func TestUnitGetDomainReport_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewDomainsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetDomainReport(ctx, "example.com")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "domain", result.Data.Type)
	assert.Equal(t, "example.com", result.Data.ID)

	// Verify domain information
	attrs := result.Data.Attributes
	assert.Equal(t, "RESERVED-Internet Assigned Numbers Authority", attrs.Registrar)
	assert.Equal(t, 1319, attrs.Reputation)
	assert.Equal(t, 75, attrs.LastAnalysisStats.Harmless)
	assert.Equal(t, 0, attrs.LastAnalysisStats.Malicious)
	assert.Equal(t, 0, attrs.LastAnalysisStats.Suspicious)
	assert.Equal(t, 11, attrs.LastAnalysisStats.Undetected)

	// Verify votes
	assert.Equal(t, 1300, attrs.TotalVotes.Harmless)
	assert.Equal(t, 10, attrs.TotalVotes.Malicious)

	// Verify categories
	assert.Contains(t, attrs.Categories, "Alexa")
	assert.Equal(t, "search engines and portals", attrs.Categories["Alexa"])

	// Verify DNS records
	require.Greater(t, len(attrs.LastDNSRecords), 0)
	assert.Equal(t, "A", attrs.LastDNSRecords[0].Type)
	assert.Equal(t, "93.184.216.34", attrs.LastDNSRecords[0].Value)

	// Verify tags
	assert.Contains(t, attrs.Tags, "popular")

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetDomainReport_EmptyDomain(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetDomainReport(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "domain is required")
}

func TestUnitGetDomainReport_NotFound(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewDomainsMock()
	mockHandler.RegisterErrorMocks()

	ctx := context.Background()
	result, err := service.GetDomainReport(ctx, "notfound.test")

	require.Error(t, err)
	require.Nil(t, result)
}

// =============================================================================
// RescanDomain Tests
// =============================================================================

func TestUnitRescanDomain_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewDomainsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.RescanDomain(ctx, "example.com")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "analysis", result.Data.Type)
	assert.Equal(t, "queued", result.Data.Attributes.Status)

	// Verify stats are present
	assert.Equal(t, 75, result.Data.Attributes.Stats.Harmless)
	assert.Equal(t, 0, result.Data.Attributes.Stats.Malicious)
	assert.Equal(t, 0, result.Data.Attributes.Stats.Suspicious)
	assert.Equal(t, 11, result.Data.Attributes.Stats.Undetected)
	assert.Equal(t, 0, result.Data.Attributes.Stats.Timeout)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitRescanDomain_EmptyDomain(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.RescanDomain(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "domain is required")
}

// =============================================================================
// GetCommentsOnDomain Tests
// =============================================================================

func TestUnitGetCommentsOnDomain_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewDomainsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetCommentsOnDomain(ctx, "example.com", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetCommentsOnDomain_EmptyDomain(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetCommentsOnDomain(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "domain is required")
}

// =============================================================================
// AddCommentToDomain Tests
// =============================================================================

func TestUnitAddCommentToDomain_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewDomainsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.AddCommentToDomain(ctx, "example.com", "This is a test comment")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "comment", result.Data.Type)
	assert.Equal(t, "This is a test comment", result.Data.Attributes.Text)
	assert.Equal(t, "<p>This is a test comment</p>", result.Data.Attributes.HTML)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitAddCommentToDomain_EmptyDomain(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddCommentToDomain(ctx, "", "Test comment")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "domain is required")
}

func TestUnitAddCommentToDomain_EmptyComment(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddCommentToDomain(ctx, "example.com", "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "comment text is required")
}

// =============================================================================
// GetObjectDescriptorsRelatedToDomain Tests
// =============================================================================

func TestUnitGetObjectDescriptorsRelatedToDomain_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewDomainsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToDomain(ctx, "example.com", "comments", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetObjectDescriptorsRelatedToDomain_EmptyDomain(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToDomain(ctx, "", "comments", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "domain is required")
}

func TestUnitGetObjectDescriptorsRelatedToDomain_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsRelatedToDomain(ctx, "example.com", "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

// =============================================================================
// GetDNSResolutionObject Tests
// =============================================================================

func TestUnitGetDNSResolutionObject_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewDomainsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetDNSResolutionObject(ctx, "93.184.216.34-example.com")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "resolution", result.Data.Type)
	assert.Equal(t, "93.184.216.34-example.com", result.Data.ID)
	assert.Equal(t, "93.184.216.34", result.Data.Attributes.IPAddress)
	assert.Equal(t, "example.com", result.Data.Attributes.HostName)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetDNSResolutionObject_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetDNSResolutionObject(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "resolution ID is required")
}

// =============================================================================
// GetVotesOnDomain Tests
// =============================================================================

func TestUnitGetVotesOnDomain_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewDomainsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.GetVotesOnDomain(ctx, "example.com", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "vote", result.Data[0].Type)
	assert.Contains(t, []string{"harmless", "malicious"}, result.Data[0].Attributes.Verdict)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetVotesOnDomain_EmptyDomain(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetVotesOnDomain(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "domain is required")
}

// =============================================================================
// AddVoteToDomain Tests
// =============================================================================

func TestUnitAddVoteToDomain_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewDomainsMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, err := service.AddVoteToDomain(ctx, "example.com", "harmless")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "vote", result.Data.Type)
	assert.Equal(t, "harmless", result.Data.Attributes.Verdict)
	assert.Equal(t, 1, result.Data.Attributes.Value)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitAddVoteToDomain_EmptyDomain(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddVoteToDomain(ctx, "", "harmless")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "domain is required")
}

func TestUnitAddVoteToDomain_EmptyVerdict(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddVoteToDomain(ctx, "example.com", "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "verdict is required")
}

func TestUnitAddVoteToDomain_InvalidVerdict(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.AddVoteToDomain(ctx, "example.com", "invalid")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "verdict must be 'harmless' or 'malicious'")
}
