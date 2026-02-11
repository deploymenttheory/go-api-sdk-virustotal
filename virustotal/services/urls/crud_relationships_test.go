package urls

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/urls/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testURLID = "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20"

// =============================================================================
// Analyses Relationship Tests
// =============================================================================

func TestUnitGetURLAnalyses_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewURLsMock()
	mockHandler.RegisterRelationshipMocks()

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipAnalyses, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "analysis", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLAnalyses_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipAnalyses, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipCollections, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "collection", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLCollections_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipCollections, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipComments, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "comment", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLComments_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipComments, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipCommunicatingFiles, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLCommunicatingFiles_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipCommunicatingFiles, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipContactedDomains, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "domain", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLContactedDomains_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipContactedDomains, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipContactedIPs, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "ip_address", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLContactedIPs_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipContactedIPs, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipDownloadedFiles, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLDownloadedFiles_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipDownloadedFiles, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipEmbeddedJSFiles, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipEmbeddedJSFiles, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipGraphs, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "graph", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLGraphs_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipGraphs, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipLastServingIPAddress, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "ip_address", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLLastServingIPAddress_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipLastServingIPAddress, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipNetworkLocation, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.NotEmpty(t, result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLNetworkLocation_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipNetworkLocation, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRedirectingURLs, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "url", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLRedirectingURLs_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRedirectingURLs, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRedirectsTo, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "url", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLRedirectsTo_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRedirectsTo, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipReferrerFiles, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLReferrerFiles_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipReferrerFiles, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipReferrerURLs, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipReferrerURLs, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRelatedComments, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRelatedComments, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRelatedReferences, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRelatedReferences, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipRelatedThreatActors, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipRelatedThreatActors, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipSubmissions, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "submission", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLSubmissions_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipSubmissions, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipUserVotes, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "vote", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLUserVotes_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipUserVotes, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipVotes, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "vote", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

func TestUnitGetURLVotesRelationship_EmptyURLID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipVotes, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, testURLID, RelationshipURLsRelatedByTrackerID, nil)

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
	result, err := service.GetObjectsRelatedToURL(ctx, "", RelationshipURLsRelatedByTrackerID, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "URL ID cannot be empty")
}
