package search_and_metadata

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/vt_enterprise/search_and_metadata/mocks"
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

	// Create Search & Metadata service
	return NewService(httpClient)
}

// =============================================================================
// Search Tests
// =============================================================================

func TestUnitSearch_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSearchAndMetadataMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.Search(ctx, "44d88612fea8a8f36de82e1278abb02f", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.Equal(t, "44d88612fea8a8f36de82e1278abb02f", result.Data[0].ID)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitSearch_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSearchAndMetadataMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	opts := &SearchOptions{
		Limit:  10,
		Cursor: "test-cursor",
	}
	result, _, err := service.Search(ctx, "test query", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitSearch_EmptyQuery(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.Search(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "search query cannot be empty")
}

// =============================================================================
// IntelligenceSearch Tests
// =============================================================================

func TestUnitIntelligenceSearch_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSearchAndMetadataMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.IntelligenceSearch(ctx, "content:hello", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotNil(t, result.Data[0].ContextAttributes)
	assert.NotNil(t, result.Data[0].ContextAttributes.Snippet)
	assert.NotEmpty(t, result.Meta.Cursor)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitIntelligenceSearch_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSearchAndMetadataMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	opts := &IntelligenceSearchOptions{
		Limit:           100,
		Order:           OrderLastSubmissionDateDesc,
		DescriptorsOnly: true,
		Cursor:          "test-cursor",
	}
	result, _, err := service.IntelligenceSearch(ctx, "type:peexe", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitIntelligenceSearch_EmptyQuery(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.IntelligenceSearch(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "search query cannot be empty")
}

// =============================================================================
// GetSearchSnippets Tests
// =============================================================================

func TestUnitGetSearchSnippets_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSearchAndMetadataMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	snippetID := "L3Z0c2FtcGxlcy8zODIzMzkzNjNhOTM2NDM2ZDM2MDM1MzFkM2IzOGEzMmUzMTUzNzM3MTM4MzY3MzBlM2Q2MzQ4MzY1M2MzYzNh"
	result, _, err := service.GetSearchSnippets(ctx, snippetID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
	assert.Contains(t, result.Data[0], "Hello World!")

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}

func TestUnitGetSearchSnippets_EmptySnippetID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, _, err := service.GetSearchSnippets(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "snippet ID cannot be empty")
}

// =============================================================================
// GetMetadata Tests
// =============================================================================

func TestUnitGetMetadata_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewSearchAndMetadataMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, _, err := service.GetMetadata(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data.Engines)
	assert.NotEmpty(t, result.Data.Privileges)
	assert.NotEmpty(t, result.Data.Relationships)
	
	// Verify some specific engines exist
	assert.Contains(t, result.Data.Engines, "Kaspersky")
	assert.Contains(t, result.Data.Engines, "Microsoft")
	
	// Verify some privileges
	assert.Contains(t, result.Data.Privileges, "intelligence")
	
	// Verify relationships structure
	assert.Contains(t, result.Data.Relationships, "file")
	assert.NotEmpty(t, result.Data.Relationships["file"])

	assert.GreaterOrEqual(t, httpmock.GetTotalCallCount(), 1)
}
