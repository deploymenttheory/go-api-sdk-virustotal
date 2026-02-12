package ipaddresses

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/ip_addresses/mocks"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupMockClient creates a client with httpmock enabled
func setupMockClient(t *testing.T) (*Service, string) {
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

	// Create IP addresses service
	return NewService(httpClient), baseURL
}

func TestUnitGetIPAddressReport_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	result, _, err := service.GetIPAddressReport(ctx, "8.8.8.8", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ip_address", result.Data.Type)
	assert.Equal(t, "8.8.8.8", result.Data.ID)

	// Verify network information
	attrs := result.Data.Attributes
	assert.Equal(t, "8.8.8.0/24", attrs.Network)
	assert.Equal(t, 15169, attrs.ASN)
	assert.Equal(t, "GOOGLE", attrs.ASOwner)
	assert.Equal(t, "US", attrs.Country)
	assert.Equal(t, "NA", attrs.Continent)
	assert.Equal(t, "ARIN", attrs.RegionalInternetRegistry)

	// Verify reputation
	assert.Equal(t, 100, attrs.Reputation)
	assert.Equal(t, 85, attrs.LastAnalysisStats.Harmless)
	assert.Equal(t, 0, attrs.LastAnalysisStats.Malicious)
	assert.Equal(t, 0, attrs.LastAnalysisStats.Suspicious)
	assert.Equal(t, 8, attrs.LastAnalysisStats.Undetected)

	// Verify votes
	assert.Equal(t, 5, attrs.TotalVotes.Harmless)
	assert.Equal(t, 0, attrs.TotalVotes.Malicious)

	// Verify tags
	assert.Contains(t, attrs.Tags, "dns")
	assert.Contains(t, attrs.Tags, "public-resolver")

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetIPAddressReport_WithRelationships(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &RequestQueryOptions{
		Relationships: "comments,resolutions",
	}
	result, _, err := service.GetIPAddressReport(ctx, "8.8.8.8", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "8.8.8.8", result.Data.ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetIPAddressReport_Unauthorized(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterErrorMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	result, _, err := service.GetIPAddressReport(ctx, "8.8.8.8", nil)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "WrongCredentialsError")

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetIPAddressReport_NotFound(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterErrorMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	result, _, err := service.GetIPAddressReport(ctx, "999.999.999.999", nil)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, err.Error(), "NotFoundError")

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetIPAddressReport_EmptyIP(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetIPAddressReport(ctx, "", nil)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ip address is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

func TestUnitRescanIPAddress_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	result, _, err := service.RescanIPAddress(ctx, "8.8.8.8")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "analysis", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
	assert.Contains(t, result.Data.Links.Self, "/analyses/")

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitRescanIPAddress_EmptyIP(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.RescanIPAddress(ctx, "")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ip address is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

func TestUnitAddCommentToIPAddress_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	commentText := "This IP is used by Google DNS and is #benign #dns"
	result, _, err := service.AddCommentToIPAddress(ctx, "8.8.8.8", commentText)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "comment", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
	assert.Contains(t, result.Data.Attributes.Text, "benign")
	assert.Contains(t, result.Data.Attributes.Tags, "benign")
	assert.Contains(t, result.Data.Attributes.Tags, "dns")
	assert.Greater(t, result.Data.Attributes.Date, int64(0))

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitAddCommentToIPAddress_EmptyIP(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddCommentToIPAddress(ctx, "", "Test comment")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ip address is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

func TestUnitAddCommentToIPAddress_EmptyComment(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddCommentToIPAddress(ctx, "8.8.8.8", "")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "comment text is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

// =============================================================================
// GetObjectDescriptorsRelatedToIPAddress Tests
// =============================================================================

func TestUnitGetObjectDescriptorsRelatedToIPAddress_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectDescriptorsRelatedToIPAddress(ctx, "8.8.8.8", "comments", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Len(t, result.Data, 2)

	// Check first descriptor
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.Equal(t, "f-8.8.8.8-1234567890", result.Data[0].ID)
	assert.NotNil(t, result.Data[0].ContextAttributes)

	// Check second descriptor
	assert.Equal(t, "comment", result.Data[1].Type)
	assert.Equal(t, "f-8.8.8.8-0987654321", result.Data[1].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectDescriptorsRelatedToIPAddress_EmptyIP(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectDescriptorsRelatedToIPAddress(ctx, "", "comments", opts)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ip address is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectDescriptorsRelatedToIPAddress_EmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectDescriptorsRelatedToIPAddress(ctx, "8.8.8.8", "", opts)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

// =============================================================================
// GetVotesOnIPAddress Tests
// =============================================================================

func TestUnitGetVotesOnIPAddress_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetVotesOptions{
		Limit: 10,
	}
	result, _, err := service.GetVotesOnIPAddress(ctx, "8.8.8.8", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Len(t, result.Data, 2)

	// Check first vote (harmless)
	assert.Equal(t, "vote", result.Data[0].Type)
	assert.Equal(t, "i-8.8.8.8-a68784ad", result.Data[0].ID)
	assert.Equal(t, "harmless", result.Data[0].Attributes.Verdict)
	assert.Equal(t, 1, result.Data[0].Attributes.Value)
	assert.Equal(t, int64(1574246328), result.Data[0].Attributes.Date)

	// Check second vote (malicious)
	assert.Equal(t, "vote", result.Data[1].Type)
	assert.Equal(t, "i-8.8.8.8-e15e57e9", result.Data[1].ID)
	assert.Equal(t, "malicious", result.Data[1].Attributes.Verdict)
	assert.Equal(t, -1, result.Data[1].Attributes.Value)
	assert.Equal(t, int64(1569486791), result.Data[1].Attributes.Date)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetVotesOnIPAddress_EmptyIP(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	opts := &GetVotesOptions{
		Limit: 10,
	}
	result, _, err := service.GetVotesOnIPAddress(ctx, "", opts)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ip address is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

// =============================================================================
// AddVoteToIPAddress Tests
// =============================================================================

func TestUnitAddVoteToIPAddress_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	verdict := "harmless"
	result, _, err := service.AddVoteToIPAddress(ctx, "8.8.8.8", verdict)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "vote", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
	assert.Equal(t, "harmless", result.Data.Attributes.Verdict)
	assert.Equal(t, 1, result.Data.Attributes.Value)
	assert.Greater(t, result.Data.Attributes.Date, int64(0))

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitAddVoteToIPAddress_EmptyIP(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToIPAddress(ctx, "", "harmless")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ip address is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

func TestUnitAddVoteToIPAddress_EmptyVerdict(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToIPAddress(ctx, "8.8.8.8", "")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "verdict is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

func TestUnitAddVoteToIPAddress_InvalidVerdict(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.AddVoteToIPAddress(ctx, "8.8.8.8", "invalid")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "verdict must be either 'harmless' or 'malicious'")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

// =============================================================================
// GetObjectsRelatedToIPAddress Tests - All Relationships
// =============================================================================

func TestUnitGetObjectsRelatedToIPAddress_Collections(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipCollections, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "collection", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_Comments(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipComments, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_CommunicatingFiles(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipCommunicatingFiles, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_DownloadedFiles(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipDownloadedFiles, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_Graphs(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipGraphs, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "graph", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_HistoricalSSLCertificates(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipHistoricalSSLCertificates, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "ssl_cert", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_HistoricalWhois(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipHistoricalWhois, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "whois", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_RelatedComments(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipRelatedComments, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_RelatedReferences(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipRelatedReferences, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "reference", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_RelatedThreatActors(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipRelatedThreatActors, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "threat_actor", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_ReferrerFiles(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipReferrerFiles, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_Resolutions(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipResolutions, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "resolution", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_URLs(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipURLs, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "url", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_UserVotes(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipUserVotes, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "vote", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_Votes(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", RelationshipVotes, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "vote", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_EmptyIP(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "", RelationshipComments, opts)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ip address is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToIPAddress_EmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit: 10,
	}
	result, _, err := service.GetObjectsRelatedToIPAddress(ctx, "8.8.8.8", "", opts)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}
