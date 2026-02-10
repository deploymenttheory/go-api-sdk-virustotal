package ipaddresses

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ipaddresses/mocks"
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

func TestGetIPAddressReport_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	result, err := service.GetIPAddressReport(ctx, "8.8.8.8", nil)

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

func TestGetIPAddressReport_WithRelationships(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	opts := &RequestQueryOptions{
		Relationships: "comments,resolutions",
	}
	result, err := service.GetIPAddressReport(ctx, "8.8.8.8", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "8.8.8.8", result.Data.ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestGetIPAddressReport_Unauthorized(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterErrorMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	result, err := service.GetIPAddressReport(ctx, "8.8.8.8", nil)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "WrongCredentialsError")

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestGetIPAddressReport_NotFound(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.IPAddressesMock{}
	mockHandler.RegisterErrorMocks(baseURL)
	defer mockHandler.CleanupMockState()

	ctx := context.Background()
	result, err := service.GetIPAddressReport(ctx, "999.999.999.999", nil)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, err.Error(), "NotFoundError")

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestGetIPAddressReport_EmptyIP(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetIPAddressReport(ctx, "", nil)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ip address is required")

	assert.Equal(t, 0, httpmock.GetTotalCallCount())
}
