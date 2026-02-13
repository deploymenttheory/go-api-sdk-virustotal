package yara_rules

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/vt_hunting/yara_rules/mocks"
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

	// Create YARA rules service
	return NewService(httpClient)
}

// =============================================================================
// ListYaraRules Tests
// =============================================================================

func TestUnitListYaraRules_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewYaraRulesMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.ListYaraRules(ctx, &ListYaraRulesOptions{
		Limit: 1,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "yara_rule", result.Data[0].Type)
	assert.Equal(t, "003e1c51ef|PK_AXA_fun", result.Data[0].ID)
	assert.Equal(t, "PK_AXA_fun", result.Data[0].Attributes.Name)
	assert.True(t, result.Data[0].Attributes.Enabled)
	assert.NotEmpty(t, result.Data[0].Attributes.Rule)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitListYaraRules_WithFilters(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewYaraRulesMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.ListYaraRules(ctx, &ListYaraRulesOptions{
		Filter: "enabled:true",
		Order:  "matches-",
		Limit:  10,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitListYaraRules_NoOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewYaraRulesMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.ListYaraRules(ctx, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

// =============================================================================
// GetYaraRule Tests
// =============================================================================

func TestUnitGetYaraRule_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewYaraRulesMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.GetYaraRule(ctx, "003e1c51ef|PK_AXA_fun")

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "yara_rule", result.Data.Type)
	assert.Equal(t, "003e1c51ef|PK_AXA_fun", result.Data.ID)
	assert.Equal(t, "PK_AXA_fun", result.Data.Attributes.Name)
	assert.Equal(t, "Thomas Damonneville", result.Data.Attributes.Author)
	assert.True(t, result.Data.Attributes.Enabled)
	assert.NotEmpty(t, result.Data.Attributes.Rule)
	assert.NotEmpty(t, result.Data.Attributes.Tags)
	assert.Contains(t, result.Data.Attributes.Tags, "AXA")
	assert.NotEmpty(t, result.Data.Attributes.Meta)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetYaraRule_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetYaraRule(ctx, "")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "YARA rule ID cannot be empty")
}

// =============================================================================
// GetObjectsRelatedToYaraRule Tests
// =============================================================================

func TestUnitGetObjectsRelatedToYaraRule_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewYaraRulesMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.GetObjectsRelatedToYaraRule(
		ctx,
		"003e1c51ef|PK_AXA_fun",
		RelationshipFiles,
		nil,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToYaraRule_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewYaraRulesMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.GetObjectsRelatedToYaraRule(
		ctx,
		"003e1c51ef|PK_AXA_fun",
		RelationshipFiles,
		&GetRelatedObjectsOptions{
			Limit: 10,
		},
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectsRelatedToYaraRule_EmptyRuleID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetObjectsRelatedToYaraRule(
		ctx,
		"",
		RelationshipFiles,
		nil,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "YARA rule ID cannot be empty")
}

func TestUnitGetObjectsRelatedToYaraRule_InvalidRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetObjectsRelatedToYaraRule(
		ctx,
		"003e1c51ef|PK_AXA_fun",
		"invalid",
		nil,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid relationship")
}

// =============================================================================
// GetObjectDescriptorsRelatedToYaraRule Tests
// =============================================================================

func TestUnitGetObjectDescriptorsRelatedToYaraRule_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewYaraRulesMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.GetObjectDescriptorsRelatedToYaraRule(
		ctx,
		"003e1c51ef|PK_AXA_fun",
		RelationshipFiles,
		nil,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "file", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectDescriptorsRelatedToYaraRule_WithOptions(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewYaraRulesMock()
	mockHandler.RegisterMocks()

	ctx := context.Background()
	result, resp, err := service.GetObjectDescriptorsRelatedToYaraRule(
		ctx,
		"003e1c51ef|PK_AXA_fun",
		RelationshipFiles,
		&GetRelatedObjectsOptions{
			Limit:  5,
			Cursor: "test-cursor",
		},
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestUnitGetObjectDescriptorsRelatedToYaraRule_EmptyRuleID(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetObjectDescriptorsRelatedToYaraRule(
		ctx,
		"",
		RelationshipFiles,
		nil,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "YARA rule ID cannot be empty")
}

func TestUnitGetObjectDescriptorsRelatedToYaraRule_InvalidRelationship(t *testing.T) {
	service := setupMockClient(t)

	ctx := context.Background()
	result, resp, err := service.GetObjectDescriptorsRelatedToYaraRule(
		ctx,
		"003e1c51ef|PK_AXA_fun",
		"invalid",
		nil,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid relationship")
}
