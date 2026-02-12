package file_behaviours

import (
	"context"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/file_behaviours/mocks"
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
// Hash Validation Helper Tests
// =============================================================================

func TestUnitIsValidMD5(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		expected bool
	}{
		{"valid MD5", "44d88612fea8a8f36de82e1278abb02f", true},
		{"valid MD5 uppercase", "44D88612FEA8A8F36DE82E1278ABB02F", true},
		{"valid MD5 mixed case", "44d88612FEA8a8f36de82e1278ABB02F", true},
		{"invalid - too short", "44d88612fea8a8f36de82e1278abb02", false},
		{"invalid - too long", "44d88612fea8a8f36de82e1278abb02f0", false},
		{"invalid - non-hex chars", "44d88612fea8a8f36de82e1278abb02g", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidMD5(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUnitIsValidSHA1(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		expected bool
	}{
		{"valid SHA-1", "356a192b7913b04c54574d18c28d46e6395428ab", true},
		{"valid SHA-1 uppercase", "356A192B7913B04C54574D18C28D46E6395428AB", true},
		{"valid SHA-1 mixed case", "356a192B7913b04C54574d18c28D46e6395428AB", true},
		{"invalid - too short", "356a192b7913b04c54574d18c28d46e6395428a", false},
		{"invalid - too long", "356a192b7913b04c54574d18c28d46e6395428abc", false},
		{"invalid - non-hex chars", "356a192b7913b04c54574d18c28d46e6395428ag", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSHA1(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUnitIsValidSHA256(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		expected bool
	}{
		{"valid SHA-256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", true},
		{"valid SHA-256 uppercase", "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08", true},
		{"valid SHA-256 mixed case", "9f86D081884c7D659a2feaA0c55aD015a3BF4f1b2b0B822cd15D6c15b0F00A08", true},
		{"invalid - too short", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0", false},
		{"invalid - too long", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a080", false},
		{"invalid - non-hex chars", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0g", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSHA256(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUnitIsValidFileHash(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		expected bool
	}{
		{"valid MD5", "44d88612fea8a8f36de82e1278abb02f", true},
		{"valid SHA-1", "356a192b7913b04c54574d18c28d46e6395428ab", true},
		{"valid SHA-256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", true},
		{"invalid - wrong length", "44d88612fea8a8f36de82e1278ab", false},
		{"invalid - non-hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidFileHash(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// GetFileBehaviourSummary Tests
// =============================================================================

func TestUnitGetFileBehaviourSummary_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetFileBehaviourSummaryMock(baseURL)

	ctx := context.Background()
	// Using a valid MD5 hash
	result, err := service.GetFileBehaviourSummaryByHashId(ctx, "44d88612fea8a8f36de82e1278abb02f")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

func TestUnitGetFileBehaviourSummary_EmptyFileID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetFileBehaviourSummaryByHashId(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "file ID is required")
}

func TestUnitGetFileBehaviourSummary_InvalidFileID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetFileBehaviourSummaryByHashId(ctx, "invalid-hash")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a valid MD5, SHA-1, or SHA-256 hash")
}

// =============================================================================
// GetAllFileBehavioursSummary Tests
// =============================================================================

func TestUnitGetAllFileBehavioursSummary_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetAllFileBehavioursSummaryMock(baseURL)

	ctx := context.Background()
	// Using valid hashes: MD5, SHA-1, SHA-256
	fileHashes := []string{
		"44d88612fea8a8f36de82e1278abb02f",
		"356a192b7913b04c54574d18c28d46e6395428ab",
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	}
	result, err := service.GetAllFileBehavioursSummary(ctx, fileHashes)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

func TestUnitGetAllFileBehavioursSummary_EmptyHashes(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetAllFileBehavioursSummary(ctx, []string{})

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "at least one file hash is required")
}

func TestUnitGetAllFileBehavioursSummary_NilHashes(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetAllFileBehavioursSummary(ctx, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "at least one file hash is required")
}

func TestUnitGetAllFileBehavioursSummary_InvalidHash(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	fileHashes := []string{"44d88612fea8a8f36de82e1278abb02f", "invalid-hash", "356a192b7913b04c54574d18c28d46e6395428ab"}
	result, err := service.GetAllFileBehavioursSummary(ctx, fileHashes)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a valid MD5, SHA-1, or SHA-256 hash")
	assert.Contains(t, err.Error(), "index 1")
}

// =============================================================================
// GetFileMitreAttackTrees Tests
// =============================================================================

func TestUnitGetFileMitreAttackTrees_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetFileMitreAttackTreesMock(baseURL)

	ctx := context.Background()
	// Using a valid SHA-256 hash
	result, err := service.GetFileMitreAttackTrees(ctx, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

func TestUnitGetFileMitreAttackTrees_EmptyFileID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetFileMitreAttackTrees(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "file ID is required")
}

func TestUnitGetFileMitreAttackTrees_InvalidFileID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetFileMitreAttackTrees(ctx, "not-a-valid-hash")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a valid MD5, SHA-1, or SHA-256 hash")
}

// =============================================================================
// GetAllFileBehaviours Tests
// =============================================================================

func TestUnitGetAllFileBehaviours_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetAllFileBehavioursMock(baseURL)

	ctx := context.Background()
	// Using a valid SHA-1 hash
	result, err := service.GetAllFileBehaviours(ctx, "356a192b7913b04c54574d18c28d46e6395428ab", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

func TestUnitGetAllFileBehaviours_ManualPagination(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetAllFileBehavioursMock(baseURL)

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit:  10,
		Cursor: "abc123",
	}
	// Using a valid SHA-1 hash
	result, err := service.GetAllFileBehaviours(ctx, "356a192b7913b04c54574d18c28d46e6395428ab", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

func TestUnitGetAllFileBehaviours_EmptyFileID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetAllFileBehaviours(ctx, "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "file ID is required")
}

func TestUnitGetAllFileBehaviours_InvalidFileID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetAllFileBehaviours(ctx, "invalid", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a valid MD5, SHA-1, or SHA-256 hash")
}

// =============================================================================
// GetFileBehaviour Tests
// =============================================================================

func TestUnitGetFileBehaviour_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetFileBehaviourMock(baseURL)

	ctx := context.Background()
	result, err := service.GetFileBehaviour(ctx, "sandbox123")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "file_behaviour", result.Data.Type)
	assert.Equal(t, "sandbox123", result.Data.ID)
}

func TestUnitGetFileBehaviour_EmptySandboxID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetFileBehaviour(ctx, "")

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "sandbox ID is required")
}

// =============================================================================
// GetObjectsRelatedToFileBehaviour Tests
// =============================================================================

func TestUnitGetObjectsRelatedToFileBehaviour_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetObjectsRelatedToFileBehaviourMock(baseURL)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToFileBehaviour(ctx, "sandbox123", "attack_techniques", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

func TestUnitGetObjectsRelatedToFileBehaviour_ManualPagination(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetObjectsRelatedToFileBehaviourMock(baseURL)

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit:  10,
		Cursor: "abc123",
	}
	result, err := service.GetObjectsRelatedToFileBehaviour(ctx, "sandbox123", "attack_techniques", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

// =============================================================================
// GetObjectDescriptorsForFileBehaviour Tests
// =============================================================================

func TestUnitGetObjectDescriptorsForFileBehaviour_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetObjectDescriptorsForFileBehaviourMock(baseURL)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsForFileBehaviour(ctx, "sandbox123", "attack_techniques", nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

func TestUnitGetObjectDescriptorsForFileBehaviour_ManualPagination(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetObjectDescriptorsForFileBehaviourMock(baseURL)

	ctx := context.Background()
	opts := &GetRelatedObjectsOptions{
		Limit:  10,
		Cursor: "abc123",
	}
	result, err := service.GetObjectDescriptorsForFileBehaviour(ctx, "sandbox123", "attack_techniques", opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

func TestUnitGetObjectDescriptorsForFileBehaviour_EmptySandboxID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsForFileBehaviour(ctx, "", "attack_techniques", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "sandbox ID is required")
}

func TestUnitGetObjectDescriptorsForFileBehaviour_EmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectDescriptorsForFileBehaviour(ctx, "sandbox123", "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}

// =============================================================================
// GetFileBehaviourHTML Tests
// =============================================================================

func TestUnitGetFileBehaviourHTML_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetFileBehaviourHTMLMock(baseURL)

	ctx := context.Background()
	result, err := service.GetFileBehaviourHTML(ctx, "sandbox123")

	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "<!DOCTYPE html>")
	assert.Contains(t, result, "Test Behaviour Report")
}

func TestUnitGetFileBehaviourHTML_EmptySandboxID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetFileBehaviourHTML(ctx, "")

	require.Error(t, err)
	assert.Empty(t, result)
	assert.Contains(t, err.Error(), "sandbox ID is required")
}

// =============================================================================
// GetFileBehaviourEVTX Tests
// =============================================================================

func TestUnitGetFileBehaviourEVTX_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetFileBehaviourEVTXMock(baseURL)

	ctx := context.Background()
	result, err := service.GetFileBehaviourEVTX(ctx, "sandbox123")

	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Greater(t, len(result), 0)
}

func TestUnitGetFileBehaviourEVTX_EmptySandboxID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetFileBehaviourEVTX(ctx, "")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "sandbox ID is required")
}

// =============================================================================
// GetFileBehaviourPCAP Tests
// =============================================================================

func TestUnitGetFileBehaviourPCAP_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetFileBehaviourPCAPMock(baseURL)

	ctx := context.Background()
	result, err := service.GetFileBehaviourPCAP(ctx, "sandbox123")

	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Greater(t, len(result), 0)
	// Verify PCAP magic number (first 4 bytes)
	assert.Equal(t, byte(0xd4), result[0])
	assert.Equal(t, byte(0xc3), result[1])
}

func TestUnitGetFileBehaviourPCAP_EmptySandboxID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetFileBehaviourPCAP(ctx, "")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "sandbox ID is required")
}

// =============================================================================
// GetFileBehaviourMemdump Tests
// =============================================================================

func TestUnitGetFileBehaviourMemdump_Success(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterGetFileBehaviourMemdumpMock(baseURL)

	ctx := context.Background()
	result, err := service.GetFileBehaviourMemdump(ctx, "sandbox123")

	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Greater(t, len(result), 0)
	// Verify PE magic number (first 2 bytes: "MZ")
	assert.Equal(t, byte(0x4d), result[0])
	assert.Equal(t, byte(0x5a), result[1])
}

func TestUnitGetFileBehaviourMemdump_EmptySandboxID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetFileBehaviourMemdump(ctx, "")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "sandbox ID is required")
}

// =============================================================================
// File Behaviour Relationship Tests
// https://docs.virustotal.com/reference/file-behaviour-summary#relationships
// =============================================================================

// TestUnitGetObjectsRelatedToFileBehaviour_File tests the file relationship
// Returns the file for a given behaviour report
// https://docs.virustotal.com/reference/file-behaviour-object-file
func TestUnitGetObjectsRelatedToFileBehaviour_File(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToFileBehaviour(ctx, "sandbox123", RelationshipFile, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)

	// Verify the file object structure
	file := result.Data[0]
	assert.Equal(t, "file", file.Type)
	assert.NotEmpty(t, file.ID)
	assert.NotEmpty(t, file.Attributes)
}

// TestUnitGetObjectsRelatedToFileBehaviour_AttackTechniques tests the attack_techniques relationship
// Returns the attack techniques observed in the behaviour report with signature context
// https://docs.virustotal.com/reference/file-behaviour-object-attack-techniques
func TestUnitGetObjectsRelatedToFileBehaviour_AttackTechniques(t *testing.T) {
	service, baseURL := setupMockClient(t)
	mockHandler := &mocks.FileBehavioursMock{}
	mockHandler.RegisterRelationshipMocks(baseURL)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToFileBehaviour(ctx, "sandbox123", RelationshipAttackTechniques, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)

	// Verify the attack technique object structure
	technique := result.Data[0]
	assert.Equal(t, "attack_technique", technique.Type)
	assert.NotEmpty(t, technique.ID)
	assert.NotEmpty(t, technique.Attributes)

	// Verify context attributes exist (signatures)
	// Note: context_attributes are parsed as map[string]any in the generic RelatedObject
	// For type-safe access, users would cast to AttackTechniqueContextAttributes
}

// TestUnitGetObjectsRelatedToFileBehaviour_EmptySandboxID validates error handling for empty sandbox ID
func TestUnitGetObjectsRelatedToFileBehaviour_ValidationEmptySandboxID(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToFileBehaviour(ctx, "", RelationshipFile, nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "sandbox ID is required")
}

// TestUnitGetObjectsRelatedToFileBehaviour_EmptyRelationship validates error handling for empty relationship
func TestUnitGetObjectsRelatedToFileBehaviour_ValidationEmptyRelationship(t *testing.T) {
	service, _ := setupMockClient(t)

	ctx := context.Background()
	result, err := service.GetObjectsRelatedToFileBehaviour(ctx, "sandbox123", "", nil)

	require.Error(t, err)
	require.Nil(t, result)
	assert.Contains(t, err.Error(), "relationship is required")
}
