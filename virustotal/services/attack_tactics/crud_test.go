package attack_tactics

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/attack_tactics/mocks"
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
// GetAttackTactic Tests
// =============================================================================

// TestUnitGetAttackTactic_Success tests successful attack tactic retrieval
func TestUnitGetAttackTactic_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTacticsMock()
	mockHandler.RegisterGetAttackTacticMock(baseURL)

	result, err := service.GetAttackTactic(context.Background(), "TA0004")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "attack_tactic", result.Data.Type)
	assert.Equal(t, "TA0004", result.Data.ID)
	assert.Equal(t, "Privilege Escalation", result.Data.Attributes.Name)
	assert.Equal(t, int64(1539735260), result.Data.Attributes.CreationDate)
	assert.Equal(t, "https://attack.mitre.org/tactics/TA0004/", result.Data.Attributes.Link)
	assert.Contains(t, result.Data.Attributes.Description, "higher-level permissions")
	assert.NotEmpty(t, result.Data.Attributes.StixID)
}

// TestUnitGetAttackTactic_EmptyID tests error handling for empty attack tactic ID
func TestUnitGetAttackTactic_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetAttackTactic(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "attack tactic ID is required")
}

// TestUnitGetAttackTactic_NotFound tests not found error handling
func TestUnitGetAttackTactic_NotFound(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTacticsMock()
	mockHandler.RegisterNotFoundErrorMock(baseURL)

	result, err := service.GetAttackTactic(context.Background(), "nonexistent-id")
	assert.Error(t, err)
	assert.Nil(t, result)
}

// =============================================================================
// GetObjectsRelatedToAttackTactic Tests
// =============================================================================

// TestUnitGetObjectsRelatedToAttackTactic_Success tests successful related objects retrieval
func TestUnitGetObjectsRelatedToAttackTactic_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTacticsMock()
	mockHandler.RegisterGetObjectsRelatedToAttackTacticMock(baseURL)

	result, err := service.GetObjectsRelatedToAttackTactic(
		context.Background(),
		"TA0004",
		RelationshipAttackTechniques,
		nil, // automatic pagination
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Data, 1)
	assert.Equal(t, "attack_technique", result.Data[0].Type)
	assert.Equal(t, "T1134", result.Data[0].ID)
	assert.NotNil(t, result.Data[0].Attributes)
}

// TestUnitGetObjectsRelatedToAttackTactic_ManualPagination tests manual pagination
func TestUnitGetObjectsRelatedToAttackTactic_ManualPagination(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTacticsMock()
	mockHandler.RegisterGetObjectsRelatedToAttackTacticMock(baseURL)

	opts := &GetRelatedObjectsOptions{
		Limit:  10,
		Cursor: "test-cursor",
	}

	result, err := service.GetObjectsRelatedToAttackTactic(
		context.Background(),
		"TA0004",
		RelationshipAttackTechniques,
		opts,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
}

// TestUnitGetObjectsRelatedToAttackTactic_EmptyID tests error handling for empty attack tactic ID
func TestUnitGetObjectsRelatedToAttackTactic_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectsRelatedToAttackTactic(
		context.Background(),
		"",
		RelationshipAttackTechniques,
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "attack tactic ID is required")
}

// TestUnitGetObjectsRelatedToAttackTactic_EmptyRelationship tests error handling for empty relationship
func TestUnitGetObjectsRelatedToAttackTactic_EmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectsRelatedToAttackTactic(
		context.Background(),
		"TA0004",
		"",
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

// =============================================================================
// GetObjectDescriptorsRelatedToAttackTactic Tests
// =============================================================================

// TestUnitGetObjectDescriptorsRelatedToAttackTactic_Success tests successful descriptor retrieval
func TestUnitGetObjectDescriptorsRelatedToAttackTactic_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTacticsMock()
	mockHandler.RegisterGetObjectDescriptorsRelatedToAttackTacticMock(baseURL)

	result, err := service.GetObjectDescriptorsRelatedToAttackTactic(
		context.Background(),
		"TA0004",
		RelationshipAttackTechniques,
		nil, // automatic pagination
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Data, 1)
	assert.Equal(t, "attack_technique", result.Data[0].Type)
	assert.Equal(t, "T1134", result.Data[0].ID)
}

// TestUnitGetObjectDescriptorsRelatedToAttackTactic_EmptyID tests error handling for empty attack tactic ID
func TestUnitGetObjectDescriptorsRelatedToAttackTactic_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectDescriptorsRelatedToAttackTactic(
		context.Background(),
		"",
		RelationshipAttackTechniques,
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "attack tactic ID is required")
}

// TestUnitGetObjectDescriptorsRelatedToAttackTactic_EmptyRelationship tests error handling for empty relationship
func TestUnitGetObjectDescriptorsRelatedToAttackTactic_EmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectDescriptorsRelatedToAttackTactic(
		context.Background(),
		"TA0004",
		"",
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}
