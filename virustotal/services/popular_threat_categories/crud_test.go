package popular_threat_categories

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/popular_threat_categories/mocks"
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
// GetPopularThreatCategories Tests
// =============================================================================

// TestUnitGetPopularThreatCategories_Success tests successful popular threat categories retrieval
func TestUnitGetPopularThreatCategories_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewPopularThreatCategoriesMock()
	mockHandler.RegisterGetPopularThreatCategoriesMock(baseURL)

	result, err := service.GetPopularThreatCategories(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Data, 3)
	assert.Equal(t, "popular_threat_category", result.Data[0].Type)
	assert.Equal(t, "trojan", result.Data[0].ID)
	assert.Equal(t, "trojan", result.Data[0].Attributes.Name)
	assert.Equal(t, "ransomware", result.Data[1].ID)
	assert.Equal(t, "adware", result.Data[2].ID)
}
