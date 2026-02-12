package code_insights

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/code_insights/mocks"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupMockClient creates a test client and activates httpmock
func setupMockClient(t *testing.T) *Service {
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
	return NewService(apiClient)
}

// =============================================================================
// AnalyseCode Tests
// =============================================================================

// TestUnitAnalyseCode_Success tests successful code analysis without history
func TestUnitAnalyseCode_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCodeInsightsMock()
	mockHandler.RegisterMocks()

	// Create a valid base64-encoded code snippet
	code := base64.StdEncoding.EncodeToString([]byte(`
		mov eax, [ebp+8]
		add eax, [ebp+12]
		ret
	`))

	result, _, err := service.AnalyseCode(context.Background(), code, CodeTypeDisassembled, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify the response contains base64-encoded data
	assert.NotEmpty(t, result.Data)
	
	// Verify the data is valid base64
	decodedData, err := base64.StdEncoding.DecodeString(result.Data)
	require.NoError(t, err)
	assert.NotEmpty(t, decodedData)
}

// TestUnitAnalyseCode_WithHistory tests successful code analysis with history
func TestUnitAnalyseCode_WithHistory(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCodeInsightsMock()
	mockHandler.RegisterMocks()

	// Create valid base64-encoded code snippet
	code := base64.StdEncoding.EncodeToString([]byte(`
		HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
	`))

	// Create history entries
	history := []HistoryEntry{
		{
			Request: base64.StdEncoding.EncodeToString([]byte("What does this registry key do?")),
			Response: HistoryResponse{
				Summary:     "Registry key analysis",
				Description: "This is a common persistence mechanism",
			},
		},
	}

	result, _, err := service.AnalyseCode(context.Background(), code, CodeTypeDecompiled, history)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify the response contains base64-encoded data
	assert.NotEmpty(t, result.Data)
	
	// Verify the data is valid base64
	decodedData, err := base64.StdEncoding.DecodeString(result.Data)
	require.NoError(t, err)
	assert.NotEmpty(t, decodedData)
}

// TestUnitAnalyseCode_InvalidBase64 tests error handling for invalid base64 code
func TestUnitAnalyseCode_InvalidBase64(t *testing.T) {
	service := setupMockClient(t)

	// Use invalid base64 (contains invalid characters)
	invalidCode := "This is not base64!"

	result, _, err := service.AnalyseCode(context.Background(), invalidCode, CodeTypeDisassembled, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "code validation failed")
}

// TestUnitAnalyseCode_EmptyCode tests error handling for empty code
func TestUnitAnalyseCode_EmptyCode(t *testing.T) {
	service := setupMockClient(t)

	result, _, err := service.AnalyseCode(context.Background(), "", CodeTypeDisassembled, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "code validation failed")
	assert.Contains(t, err.Error(), "cannot be empty")
}

// TestUnitAnalyseCode_InvalidCodeType tests error handling for invalid code type
func TestUnitAnalyseCode_InvalidCodeType(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCodeInsightsMock()
	mockHandler.RegisterMocks()

	code := base64.StdEncoding.EncodeToString([]byte("test code"))

	result, _, err := service.AnalyseCode(context.Background(), code, "invalid_type", nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "code type validation failed")
}

// TestUnitAnalyseCode_EmptyCodeType tests error handling for empty code type
func TestUnitAnalyseCode_EmptyCodeType(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCodeInsightsMock()
	mockHandler.RegisterMocks()

	code := base64.StdEncoding.EncodeToString([]byte("test code"))

	result, _, err := service.AnalyseCode(context.Background(), code, "", nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "code type validation failed")
	assert.Contains(t, err.Error(), "cannot be empty")
}

// TestUnitAnalyseCode_InvalidHistoryBase64 tests error handling for invalid base64 in history
func TestUnitAnalyseCode_InvalidHistoryBase64(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCodeInsightsMock()
	mockHandler.RegisterMocks()

	code := base64.StdEncoding.EncodeToString([]byte("test code"))

	// Create history with invalid base64 request
	history := []HistoryEntry{
		{
			Request: "Not valid base64!",
			Response: HistoryResponse{
				Summary:     "Test",
				Description: "Test description",
			},
		},
	}

	result, _, err := service.AnalyseCode(context.Background(), code, CodeTypeDisassembled, history)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "history entry 0 request validation failed")
}

// TestUnitAnalyseCode_DisassembledCodeType tests code analysis with disassembled code type
func TestUnitAnalyseCode_DisassembledCodeType(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCodeInsightsMock()
	mockHandler.RegisterMocks()

	// Create a valid base64-encoded disassembled code snippet
	code := base64.StdEncoding.EncodeToString([]byte(`
		push ebp
		mov ebp, esp
		sub esp, 0x10
		ret
	`))

	result, _, err := service.AnalyseCode(context.Background(), code, CodeTypeDisassembled, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

// TestUnitAnalyseCode_DecompiledCodeType tests code analysis with decompiled code type
func TestUnitAnalyseCode_DecompiledCodeType(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCodeInsightsMock()
	mockHandler.RegisterMocks()

	// Create a valid base64-encoded decompiled code snippet
	code := base64.StdEncoding.EncodeToString([]byte(`
		int add(int a, int b) {
			return a + b;
		}
	`))

	result, _, err := service.AnalyseCode(context.Background(), code, CodeTypeDecompiled, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

// TestUnitAnalyseCode_MultipleHistoryEntries tests code analysis with multiple history entries
func TestUnitAnalyseCode_MultipleHistoryEntries(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCodeInsightsMock()
	mockHandler.RegisterMocks()

	code := base64.StdEncoding.EncodeToString([]byte("test code"))

	// Create multiple history entries
	history := []HistoryEntry{
		{
			Request: base64.StdEncoding.EncodeToString([]byte("First question")),
			Response: HistoryResponse{
				Summary:     "First answer summary",
				Description: "First answer description",
			},
		},
		{
			Request: base64.StdEncoding.EncodeToString([]byte("Second question")),
			Response: HistoryResponse{
				Summary:     "Second answer summary",
				Description: "Second answer description",
			},
		},
		{
			Request: base64.StdEncoding.EncodeToString([]byte("Third question")),
			Response: HistoryResponse{
				Summary:     "Third answer summary",
				Description: "Third answer description",
			},
		},
	}

	result, _, err := service.AnalyseCode(context.Background(), code, CodeTypeDisassembled, history)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}

// TestUnitAnalyseCode_LargeCodeBlock tests code analysis with a large code block
func TestUnitAnalyseCode_LargeCodeBlock(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewCodeInsightsMock()
	mockHandler.RegisterMocks()

	// Create a larger code block
	largeCode := `
		int main() {
			int x = 10;
			int y = 20;
			int z = x + y;
			printf("Result: %d\n", z);
			
			for (int i = 0; i < 10; i++) {
				printf("Iteration: %d\n", i);
			}
			
			return 0;
		}
		
		void helper_function() {
			// Some helper code
			int a = 5;
			int b = 15;
			return a * b;
		}
	`
	
	code := base64.StdEncoding.EncodeToString([]byte(largeCode))

	result, _, err := service.AnalyseCode(context.Background(), code, CodeTypeDecompiled, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Data)
}
