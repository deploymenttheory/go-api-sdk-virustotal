package attack_techniques

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/attack_techniques/mocks"
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

const testAttackTechniqueID = "T1548"

// =============================================================================
// GetAttackTechnique Tests
// =============================================================================

// TestUnitGetAttackTechnique_Success tests successful attack technique retrieval
func TestUnitGetAttackTechnique_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTechniquesMock()
	mockHandler.RegisterGetAttackTechniqueMock(baseURL)

	result, err := service.GetAttackTechnique(context.Background(), "T1548")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "attack_technique", result.Data.Type)
	assert.Equal(t, "T1548", result.Data.ID)
	assert.Equal(t, "Abuse Elevation Control Mechanism", result.Data.Attributes.Name)
	assert.Contains(t, result.Data.Attributes.Description, "elevate privileges")
	assert.NotEmpty(t, result.Data.Attributes.StixID)
}

// TestUnitGetAttackTechnique_EmptyID tests error handling for empty attack technique ID
func TestUnitGetAttackTechnique_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetAttackTechnique(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "attack technique ID is required")
}

// TestUnitGetAttackTechnique_NotFound tests not found error handling
func TestUnitGetAttackTechnique_NotFound(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTechniquesMock()
	mockHandler.RegisterNotFoundErrorMock(baseURL)

	result, err := service.GetAttackTechnique(context.Background(), "nonexistent-id")
	assert.Error(t, err)
	assert.Nil(t, result)
}

// =============================================================================
// GetObjectsRelatedToAttackTechnique Tests
// =============================================================================

// TestUnitGetObjectsRelatedToAttackTechnique_Success tests successful related objects retrieval
func TestUnitGetObjectsRelatedToAttackTechnique_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTechniquesMock()
	mockHandler.RegisterGetObjectsRelatedToAttackTechniqueMock(baseURL)

	result, err := service.GetObjectsRelatedToAttackTechnique(
		context.Background(),
		"T1548",
		RelationshipAttackTactics,
		nil, // automatic pagination
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Data, 1)
	assert.Equal(t, "attack_tactic", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
	assert.NotNil(t, result.Data[0].Attributes)
}

// TestUnitGetObjectsRelatedToAttackTechnique_EmptyID tests error handling for empty attack technique ID
func TestUnitGetObjectsRelatedToAttackTechnique_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectsRelatedToAttackTechnique(
		context.Background(),
		"",
		RelationshipAttackTactics,
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "attack technique ID is required")
}

// TestUnitGetObjectsRelatedToAttackTechnique_EmptyRelationship tests error handling for empty relationship
func TestUnitGetObjectsRelatedToAttackTechnique_EmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectsRelatedToAttackTechnique(
		context.Background(),
		"T1548",
		"",
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

// =============================================================================
// GetObjectDescriptorsRelatedToAttackTechnique Tests
// =============================================================================

// TestUnitGetObjectDescriptorsRelatedToAttackTechnique_Success tests successful descriptor retrieval
func TestUnitGetObjectDescriptorsRelatedToAttackTechnique_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTechniquesMock()
	mockHandler.RegisterGetObjectDescriptorsRelatedToAttackTechniqueMock(baseURL)

	result, err := service.GetObjectDescriptorsRelatedToAttackTechnique(
		context.Background(),
		"T1548",
		RelationshipAttackTactics,
		nil, // automatic pagination
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Data, 1)
	assert.Equal(t, "attack_tactic", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

// TestUnitGetObjectDescriptorsRelatedToAttackTechnique_EmptyID tests error handling for empty attack technique ID
func TestUnitGetObjectDescriptorsRelatedToAttackTechnique_EmptyID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectDescriptorsRelatedToAttackTechnique(
		context.Background(),
		"",
		RelationshipAttackTactics,
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "attack technique ID is required")
}

// TestUnitGetObjectDescriptorsRelatedToAttackTechnique_EmptyRelationship tests error handling for empty relationship
func TestUnitGetObjectDescriptorsRelatedToAttackTechnique_EmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectDescriptorsRelatedToAttackTechnique(
		context.Background(),
		"T1548",
		"",
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

// =============================================================================
// Attack Tactics Relationship Tests
// =============================================================================

// TestUnitGetAttackTechniqueAttackTactics_Success tests successful attack_tactics relationship retrieval
func TestUnitGetAttackTechniqueAttackTactics_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTechniquesMock()
	mockHandler.RegisterRelationshipMocks(baseURL)

	result, err := service.GetObjectsRelatedToAttackTechnique(
		context.Background(),
		testAttackTechniqueID,
		RelationshipAttackTactics,
		&GetRelatedObjectsOptions{Limit: 10},
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "attack_tactic", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

// TestUnitGetAttackTechniqueAttackTactics_EmptyTechniqueID tests error handling for empty technique ID
func TestUnitGetAttackTechniqueAttackTactics_EmptyTechniqueID(t *testing.T) {
	service, _ := setupMockClient(t)

	result, err := service.GetObjectsRelatedToAttackTechnique(
		context.Background(),
		"",
		RelationshipAttackTactics,
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "attack technique ID is required")
}

// =============================================================================
// Parent Technique Relationship Tests
// =============================================================================

// TestUnitGetAttackTechniqueParentTechnique_Success tests successful parent_technique relationship retrieval
func TestUnitGetAttackTechniqueParentTechnique_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTechniquesMock()
	mockHandler.RegisterRelationshipMocks(baseURL)

	result, err := service.GetObjectsRelatedToAttackTechnique(
		context.Background(),
		"T1548.001",
		RelationshipParentTechnique,
		&GetRelatedObjectsOptions{Limit: 10},
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "attack_technique", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

// =============================================================================
// Revoking Technique Relationship Tests
// =============================================================================

// TestUnitGetAttackTechniqueRevokingTechnique_Success tests successful revoking_technique relationship retrieval
func TestUnitGetAttackTechniqueRevokingTechnique_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTechniquesMock()
	mockHandler.RegisterRelationshipMocks(baseURL)

	result, err := service.GetObjectsRelatedToAttackTechnique(
		context.Background(),
		"T1156",
		RelationshipRevokingTechnique,
		&GetRelatedObjectsOptions{Limit: 10},
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "attack_technique", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

// =============================================================================
// Subtechniques Relationship Tests
// =============================================================================

// TestUnitGetAttackTechniqueSubtechniques_Success tests successful subtechniques relationship retrieval
func TestUnitGetAttackTechniqueSubtechniques_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTechniquesMock()
	mockHandler.RegisterRelationshipMocks(baseURL)

	result, err := service.GetObjectsRelatedToAttackTechnique(
		context.Background(),
		testAttackTechniqueID,
		RelationshipSubtechniques,
		&GetRelatedObjectsOptions{Limit: 10},
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "attack_technique", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

// =============================================================================
// Threat Actors Relationship Tests
// =============================================================================

// TestUnitGetAttackTechniqueThreatActors_Success tests successful threat_actors relationship retrieval
func TestUnitGetAttackTechniqueThreatActors_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := mocks.NewAttackTechniquesMock()
	mockHandler.RegisterRelationshipMocks(baseURL)

	result, err := service.GetObjectsRelatedToAttackTechnique(
		context.Background(),
		testAttackTechniqueID,
		RelationshipThreatActors,
		&GetRelatedObjectsOptions{Limit: 10},
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Greater(t, len(result.Data), 0)
	assert.Equal(t, "threat_actor", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}
