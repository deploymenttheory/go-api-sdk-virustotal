package analyses

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/analyses/mocks"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupMockClient creates a test client and activates httpmock
func setupMockClient(t *testing.T) (*Service, string) {
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
	return NewService(apiClient), baseURL
}

// =============================================================================
// GetAnalysis Tests
// =============================================================================

// TestUnitGetAnalysis_Success tests successful analysis retrieval
func TestUnitGetAnalysis_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAnalysesMock()
	mockHandler.RegisterGetAnalysisMock(baseURL)

	result, err := service.GetAnalysis(context.Background(), "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw==")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "analysis", result.Data.Type)
	assert.Equal(t, "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw==", result.Data.ID)
	assert.Equal(t, "completed", result.Data.Attributes.Status)
	assert.Equal(t, 5, result.Data.Attributes.Stats.Malicious)
	assert.Equal(t, 50, result.Data.Attributes.Stats.Harmless)
	assert.NotEmpty(t, result.Data.Attributes.Results)
}

// TestUnitGetAnalysis_EmptyID tests error handling for empty analysis ID
func TestUnitGetAnalysis_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetAnalysis(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "analysis ID is required")
}

// TestUnitGetAnalysis_NotFound tests not found error handling
func TestUnitGetAnalysis_NotFound(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAnalysesMock()
	mockHandler.RegisterNotFoundErrorMock(baseURL)

	result, err := service.GetAnalysis(context.Background(), "nonexistent-id")
	assert.Error(t, err)
	assert.Nil(t, result)
}

// =============================================================================
// GetSubmission Tests
// =============================================================================

// TestUnitGetSubmission_Success tests successful submission retrieval
func TestUnitGetSubmission_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAnalysesMock()
	mockHandler.RegisterGetSubmissionMock(baseURL)

	result, err := service.GetSubmission(context.Background(), "f-e7a2b2c164285d1203062b752d87d2f72ca9e2810b52a61f281828f28722d609-1632333331")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "submission", result.Data.Type)
	assert.Equal(t, "f-e7a2b2c164285d1203062b752d87d2f72ca9e2810b52a61f281828f28722d609-1632333331", result.Data.ID)
	assert.Equal(t, int64(1632333331), result.Data.Attributes.Date)
	assert.Equal(t, "api", result.Data.Attributes.Interface)
	assert.Equal(t, "US", result.Data.Attributes.Country)
}

// TestUnitGetSubmission_EmptyID tests error handling for empty submission ID
func TestUnitGetSubmission_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetSubmission(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "submission ID is required")
}

// =============================================================================
// GetOperation Tests
// =============================================================================

// TestUnitGetOperation_Success tests successful operation retrieval
func TestUnitGetOperation_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAnalysesMock()
	mockHandler.RegisterGetOperationMock(baseURL)

	result, err := service.GetOperation(context.Background(), "334b32b7fa5b47c78369600fad91d1b4")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "operation", result.Data.Type)
	assert.Equal(t, "334b32b7fa5b47c78369600fad91d1b4", result.Data.ID)
	assert.Equal(t, "finished", result.Data.Attributes.Status)
}

// TestUnitGetOperation_EmptyID tests error handling for empty operation ID
func TestUnitGetOperation_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetOperation(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "operation ID is required")
}

// =============================================================================
// GetObjectsRelatedToAnalysis Tests
// =============================================================================

// TestUnitGetObjectsRelatedToAnalysis_Success tests successful related objects retrieval
func TestUnitGetObjectsRelatedToAnalysis_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAnalysesMock()
	mockHandler.RegisterGetObjectsRelatedToAnalysisMock(baseURL)

	result, err := service.GetObjectsRelatedToAnalysis(
		context.Background(),
		"test-analysis-id",
		RelationshipItem,
		nil, // automatic pagination
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Data, 1)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.Equal(t, "44d88612fea8a8f36de82e1278abb02f", result.Data[0].ID)
}

// TestUnitGetObjectsRelatedToAnalysis_ManualPagination tests manual pagination
func TestUnitGetObjectsRelatedToAnalysis_ManualPagination(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAnalysesMock()
	mockHandler.RegisterGetObjectsRelatedToAnalysisMock(baseURL)

	opts := &GetRelatedObjectsOptions{
		Limit:  10,
		Cursor: "test-cursor",
	}

	result, err := service.GetObjectsRelatedToAnalysis(
		context.Background(),
		"test-analysis-id",
		RelationshipItem,
		opts,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
}

// TestUnitGetObjectsRelatedToAnalysis_EmptyID tests error handling for empty analysis ID
func TestUnitGetObjectsRelatedToAnalysis_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectsRelatedToAnalysis(
		context.Background(),
		"",
		RelationshipItem,
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "analysis ID is required")
}

// TestUnitGetObjectsRelatedToAnalysis_EmptyRelationship tests error handling for empty relationship
func TestUnitGetObjectsRelatedToAnalysis_EmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectsRelatedToAnalysis(
		context.Background(),
		"test-id",
		"",
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

// =============================================================================
// GetObjectDescriptorsRelatedToAnalysis Tests
// =============================================================================

// TestUnitGetObjectDescriptorsRelatedToAnalysis_Success tests successful descriptor retrieval
func TestUnitGetObjectDescriptorsRelatedToAnalysis_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAnalysesMock()
	mockHandler.RegisterGetObjectDescriptorsRelatedToAnalysisMock(baseURL)

	result, err := service.GetObjectDescriptorsRelatedToAnalysis(
		context.Background(),
		"test-analysis-id",
		RelationshipItem,
		nil, // automatic pagination
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Data, 1)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.Equal(t, "44d88612fea8a8f36de82e1278abb02f", result.Data[0].ID)
}

// TestUnitGetObjectDescriptorsRelatedToAnalysis_EmptyID tests error handling for empty analysis ID
func TestUnitGetObjectDescriptorsRelatedToAnalysis_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectDescriptorsRelatedToAnalysis(
		context.Background(),
		"",
		RelationshipItem,
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "analysis ID is required")
}

// TestUnitGetObjectDescriptorsRelatedToAnalysis_EmptyRelationship tests error handling for empty relationship
func TestUnitGetObjectDescriptorsRelatedToAnalysis_EmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectDescriptorsRelatedToAnalysis(
		context.Background(),
		"test-id",
		"",
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}
