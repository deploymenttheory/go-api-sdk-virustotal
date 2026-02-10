package files

import (
	"context"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/files/mocks"
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

// TestUploadFile_Success tests successful file upload
func TestUnitUploadFile_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	fileContent := "test file content"
	request := &UploadFileRequest{
		File:     strings.NewReader(fileContent),
		Filename: "test.txt",
		FileSize: int64(len(fileContent)),
	}

	result, err := service.UploadFile(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "analysis", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
}

// TestUnitUploadFile_WithProgressCallback tests file upload with progress tracking
func TestUnitUploadFile_WithProgressCallback(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	fileContent := "test file content for progress tracking"
	var progressCalled bool
	var lastBytesWritten int64
	var lastTotalBytes int64

	request := &UploadFileRequest{
		File:     strings.NewReader(fileContent),
		Filename: "test_progress.txt",
		FileSize: int64(len(fileContent)),
		ProgressCallback: func(fieldName, fileName string, bytesWritten, totalBytes int64) {
			progressCalled = true
			lastBytesWritten = bytesWritten
			lastTotalBytes = totalBytes
			assert.Equal(t, "file", fieldName)
			assert.Equal(t, "test_progress.txt", fileName)
		},
	}

	result, err := service.UploadFile(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "analysis", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
	
	// Progress callback should have been called
	assert.True(t, progressCalled, "Progress callback should have been called")
	assert.Equal(t, int64(len(fileContent)), lastTotalBytes)
	assert.Greater(t, lastBytesWritten, int64(0))
}

// TestUploadFile_MissingFile tests error when file is missing
func TestUnitUploadFile_MissingFile(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.UploadFile(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file is required")
}

// TestUploadFile_MissingFilename tests error when filename is missing
func TestUnitUploadFile_MissingFilename(t *testing.T) {
	service := setupMockClient(t)

	fileContent := "test"
	request := &UploadFileRequest{
		File:     strings.NewReader(fileContent),
		FileSize: int64(len(fileContent)),
	}

	_, err := service.UploadFile(context.Background(), request)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "filename is required")
}

// TestGetUploadURL_Success tests successful upload URL retrieval
func TestUnitGetUploadURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetUploadURL(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
	assert.Contains(t, result.Data, "https://")
}

// TestGetFileReport_Success tests successful file report retrieval
func TestUnitGetFileReport_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetFileReport(context.Background(), "44d88612fea8a8f36de82e1278abb02f")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "file", result.Data.Type)
	assert.Equal(t, "44d88612fea8a8f36de82e1278abb02f", result.Data.ID)
	assert.NotEmpty(t, result.Data.Attributes.MD5)
	assert.NotEmpty(t, result.Data.Attributes.SHA256)
}

// TestGetFileReport_EmptyID tests error when file ID is empty
func TestUnitGetFileReport_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetFileReport(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestRescanFile_Success tests successful file rescan
func TestUnitRescanFile_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.RescanFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "analysis", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
}

// TestRescanFile_EmptyID tests error when file ID is empty
func TestUnitRescanFile_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.RescanFile(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestGetFileDownloadURL_Success tests successful download URL retrieval
func TestUnitGetFileDownloadURL_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetFileDownloadURL(context.Background(), "44d88612fea8a8f36de82e1278abb02f")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
	assert.Contains(t, result.Data, "https://")
}

// TestGetFileDownloadURL_EmptyID tests error when file ID is empty
func TestUnitGetFileDownloadURL_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetFileDownloadURL(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestDownloadFile_Success tests successful file download redirect
func TestUnitDownloadFile_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.DownloadFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
	assert.Contains(t, result.Data, "https://")
}

// TestDownloadFile_EmptyID tests error when file ID is empty
func TestUnitDownloadFile_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.DownloadFile(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestGetCommentsOnFile_Success tests successful comments retrieval with auto-pagination
func TestUnitGetCommentsOnFile_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetCommentsOnFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "comment", result.Data[0].Type)
}

// TestGetCommentsOnFile_ManualPagination tests manual pagination
func TestUnitGetCommentsOnFile_ManualPagination(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	opts := &GetRelatedObjectsOptions{
		Limit:  10,
		Cursor: "abc123",
	}

	result, err := service.GetCommentsOnFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", opts)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
}

// TestGetCommentsOnFile_EmptyID tests error when file ID is empty
func TestUnitGetCommentsOnFile_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetCommentsOnFile(context.Background(), "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestAddCommentToFile_Success tests successful comment addition
func TestUnitAddCommentToFile_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.AddCommentToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "This is a test comment")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "comment", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
	assert.Equal(t, "This is a test comment", result.Data.Attributes.Text)
	assert.Equal(t, "<p>This is a test comment</p>", result.Data.Attributes.HTML)
}

// TestAddCommentToFile_EmptyID tests error when file ID is empty
func TestUnitAddCommentToFile_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.AddCommentToFile(context.Background(), "", "comment")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestAddCommentToFile_EmptyComment tests error when comment is empty
func TestUnitAddCommentToFile_EmptyComment(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.AddCommentToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "comment text is required")
}

// TestGetObjectsRelatedToFile_Success tests successful related objects retrieval with auto-pagination
func TestUnitGetObjectsRelatedToFile_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetObjectsRelatedToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "contacted_domains", nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "domain", result.Data[0].Type)
}

// TestGetObjectsRelatedToFile_ManualPagination tests manual pagination
func TestUnitGetObjectsRelatedToFile_ManualPagination(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	opts := &GetRelatedObjectsOptions{
		Limit:  10,
		Cursor: "abc123",
	}

	result, err := service.GetObjectsRelatedToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "contacted_domains", opts)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
}

// TestGetObjectsRelatedToFile_EmptyID tests error when file ID is empty
func TestUnitGetObjectsRelatedToFile_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetObjectsRelatedToFile(context.Background(), "", "contacted_domains", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestGetObjectsRelatedToFile_EmptyRelationship tests error when relationship is empty
func TestUnitGetObjectsRelatedToFile_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetObjectsRelatedToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "relationship is required")
}

// TestGetObjectDescriptorsRelatedToFile_Success tests successful object descriptors retrieval
func TestUnitGetObjectDescriptorsRelatedToFile_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetObjectDescriptorsRelatedToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "contacted_domains", nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "domain", result.Data[0].Type)
	assert.NotEmpty(t, result.Data[0].ID)
}

// TestGetObjectDescriptorsRelatedToFile_EmptyID tests error when file ID is empty
func TestUnitGetObjectDescriptorsRelatedToFile_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetObjectDescriptorsRelatedToFile(context.Background(), "", "contacted_domains", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestGetObjectDescriptorsRelatedToFile_EmptyRelationship tests error when relationship is empty
func TestUnitGetObjectDescriptorsRelatedToFile_EmptyRelationship(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetObjectDescriptorsRelatedToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "relationship is required")
}

// TestGetSigmaRule_Success tests successful Sigma rule retrieval
func TestUnitGetSigmaRule_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetSigmaRule(context.Background(), "sigma-rule-123")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "sigma_rule", result.Data.Type)
	assert.Equal(t, "sigma-rule-123", result.Data.ID)
	assert.NotEmpty(t, result.Data.Attributes.RuleName)
}

// TestGetSigmaRule_EmptyID tests error when rule ID is empty
func TestUnitGetSigmaRule_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetSigmaRule(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sigma rule ID is required")
}

// TestGetYARARuleset_Success tests successful YARA ruleset retrieval
func TestUnitGetYARARuleset_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetYARARuleset(context.Background(), "yara-ruleset-123")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "yara_ruleset", result.Data.Type)
	assert.Equal(t, "yara-ruleset-123", result.Data.ID)
	assert.NotEmpty(t, result.Data.Attributes.Name)
}

// TestGetYARARuleset_EmptyID tests error when ruleset ID is empty
func TestUnitGetYARARuleset_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetYARARuleset(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "YARA ruleset ID is required")
}

// TestGetVotesOnFile_Success tests successful votes retrieval with auto-pagination
func TestUnitGetVotesOnFile_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.GetVotesOnFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
	assert.Equal(t, "vote", result.Data[0].Type)
}

// TestGetVotesOnFile_ManualPagination tests manual pagination
func TestUnitGetVotesOnFile_ManualPagination(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	opts := &GetVotesOptions{
		Limit:  10,
		Cursor: "abc123",
	}

	result, err := service.GetVotesOnFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", opts)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Data)
}

// TestGetVotesOnFile_EmptyID tests error when file ID is empty
func TestUnitGetVotesOnFile_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.GetVotesOnFile(context.Background(), "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestAddVoteToFile_Success tests successful vote addition
func TestUnitAddVoteToFile_Success(t *testing.T) {
	service := setupMockClient(t)
	mockHandler := mocks.NewFilesMock()
	mockHandler.RegisterMocks()

	result, err := service.AddVoteToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "harmless")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "vote", result.Data.Type)
	assert.NotEmpty(t, result.Data.ID)
	assert.Equal(t, "harmless", result.Data.Attributes.Verdict)
	assert.Equal(t, 1, result.Data.Attributes.Value)
}

// TestAddVoteToFile_EmptyID tests error when file ID is empty
func TestUnitAddVoteToFile_EmptyID(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.AddVoteToFile(context.Background(), "", "harmless")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file ID is required")
}

// TestAddVoteToFile_EmptyVerdict tests error when verdict is empty
func TestUnitAddVoteToFile_EmptyVerdict(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.AddVoteToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verdict is required")
}

// TestAddVoteToFile_InvalidVerdict tests error when verdict is invalid
func TestUnitAddVoteToFile_InvalidVerdict(t *testing.T) {
	service := setupMockClient(t)

	_, err := service.AddVoteToFile(context.Background(), "44d88612fea8a8f36de82e1278abb02f", "invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verdict must be 'harmless' or 'malicious'")
}
