package acceptance

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// UploadFile Tests
// =============================================================================

// TestAcceptance_Files_UploadFile_SmallFile tests uploading a file smaller than 32MB
func TestAcceptance_Files_UploadFile_SmallFile(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "⬆️  Upload Small File", "Testing UploadFile with file < 32MB")

		// Create a small test file (1MB of random data)
		fileSize := int64(1 * 1024 * 1024) // 1MB
		fileData := make([]byte, fileSize)
		_, err := rand.Read(fileData)
		if err != nil {
			t.Fatalf("Failed to generate test file data: %v", err)
		}

		fileReader := bytes.NewReader(fileData)

		request := &files.UploadFileRequest{
			File:     fileReader,
			Filename: "test_small_file.bin",
			FileSize: fileSize,
		}

		result, resp, err := service.UploadFile(ctx, request)
		
		// Check for quota exceeded
		if err != nil && resp != nil && resp.StatusCode == 429 {
			LogTestWarning(t, "API quota exceeded (429) - test skipped")
			t.Skip("Skipping test - API quota exceeded")
		}

		AssertNoError(t, err, "UploadFile should not return an error")
		AssertNotNil(t, result, "UploadFile result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Upload data should not be nil")
		assert.Equal(t, "analysis", result.Data.Type, "Response type should be 'analysis'")
		assert.NotEmpty(t, result.Data.ID, "Analysis ID should not be empty")

		LogTestSuccess(t, "Small file uploaded successfully")
		LogTestSuccess(t, "Analysis ID: %s", result.Data.ID)
		LogTestSuccess(t, "File size: %d bytes (< 32MB, used direct /files endpoint)", fileSize)
	})
}

// TestAcceptance_Files_UploadFile_LargeFile tests uploading a file larger than 32MB
func TestAcceptance_Files_UploadFile_LargeFile(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "⬆️  Upload Large File", "Testing UploadFile with file > 32MB")

		// Create a large test file (33MB of random data, slightly over 32MB limit)
		fileSize := int64(33 * 1024 * 1024) // 33MB
		fileData := make([]byte, fileSize)
		_, err := rand.Read(fileData)
		if err != nil {
			t.Fatalf("Failed to generate test file data: %v", err)
		}

		fileReader := bytes.NewReader(fileData)

		// Track progress with callback
		var lastProgress float32
		progressCallback := func(fieldName string, fileName string, bytesWritten int64, totalBytes int64) {
			if totalBytes > 0 {
				progress := float32(bytesWritten) / float32(totalBytes) * 100
				// Log progress at 25%, 50%, 75%, and 100%
				if progress >= lastProgress+25 || progress >= 99.9 {
					t.Logf("Upload progress: %.2f%% (%d/%d bytes)", progress, bytesWritten, totalBytes)
					lastProgress = progress
				}
			}
		}

		request := &files.UploadFileRequest{
			File:             fileReader,
			Filename:         "test_large_file.bin",
			FileSize:         fileSize,
			ProgressCallback: progressCallback,
		}

		result, resp, err := service.UploadFile(ctx, request)
		
		// Check for quota exceeded
		if err != nil && resp != nil && resp.StatusCode == 429 {
			LogTestWarning(t, "API quota exceeded (429) - test skipped")
			t.Skip("Skipping test - API quota exceeded")
		}

		AssertNoError(t, err, "UploadFile should not return an error")
		AssertNotNil(t, result, "UploadFile result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Upload data should not be nil")
		assert.Equal(t, "analysis", result.Data.Type, "Response type should be 'analysis'")
		assert.NotEmpty(t, result.Data.ID, "Analysis ID should not be empty")

		LogTestSuccess(t, "Large file uploaded successfully")
		LogTestSuccess(t, "Analysis ID: %s", result.Data.ID)
		LogTestSuccess(t, "File size: %d bytes (> 32MB, used /files/upload_url endpoint)", fileSize)
	})
}

// =============================================================================
// GetFileReport Tests
// =============================================================================

// TestAcceptance_Files_GetFileReport tests retrieving file information by hash
func TestAcceptance_Files_GetFileReport(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "📄 File Report", "Testing GetFileReport with hash: %s", Config.KnownFileHash)

		result, resp, err := service.GetFileReport(ctx, Config.KnownFileHash)
		AssertNoError(t, err, "GetFileReport should not return an error")
		AssertNotNil(t, result, "GetFileReport result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")
		assert.NotNil(t, resp.Headers, "Response headers should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "File data should not be nil")
		assert.Equal(t, "file", result.Data.Type, "Response type should be 'file'")
		assert.NotEmpty(t, result.Data.ID, "File ID should not be empty")
		assert.NotNil(t, result.Data.Attributes, "File attributes should not be nil")

		// Validate file attributes
		attrs := result.Data.Attributes
		assert.NotEmpty(t, attrs.MD5, "MD5 hash should not be empty")
		assert.NotEmpty(t, attrs.SHA1, "SHA1 hash should not be empty")
		assert.NotEmpty(t, attrs.SHA256, "SHA256 hash should not be empty")
		assert.Greater(t, attrs.Size, int64(0), "File size should be greater than 0")
		
		// EICAR file should be detected as malicious by most engines
		assert.NotNil(t, attrs.LastAnalysisStats, "Analysis stats should not be nil")
		assert.Greater(t, attrs.LastAnalysisStats.Malicious, 0, "EICAR file should be detected as malicious")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Harmless, 0, "Harmless count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Suspicious, 0, "Suspicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Undetected, 0, "Undetected count should be >= 0")
		
		// Validate timestamps
		assert.Greater(t, attrs.LastAnalysisDate, int64(0), "Last analysis date should be valid")
		assert.Greater(t, attrs.FirstSubmissionDate, int64(0), "First submission date should be valid")
		
		// Validate reputation and vote counts
		assert.NotNil(t, attrs.TotalVotes, "Total votes should not be nil")

		LogTestSuccess(t, "File SHA256: %s, Size: %d bytes", attrs.SHA256, attrs.Size)
		LogTestSuccess(t, "Analysis Stats - Malicious: %d, Suspicious: %d, Harmless: %d, Undetected: %d",
			attrs.LastAnalysisStats.Malicious,
			attrs.LastAnalysisStats.Suspicious,
			attrs.LastAnalysisStats.Harmless,
			attrs.LastAnalysisStats.Undetected)
		LogTestSuccess(t, "Total Votes - Harmless: %d, Malicious: %d", attrs.TotalVotes.Harmless, attrs.TotalVotes.Malicious)
	})
}

// TestAcceptance_Files_GetFileReport_InvalidHash tests error handling
func TestAcceptance_Files_GetFileReport_InvalidHash(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "❌ Error Test", "Testing GetFileReport with invalid hash")

		// Use a non-existent hash
		result, resp, err := service.GetFileReport(ctx, "0000000000000000000000000000000000000000000000000000000000000000")

		// We expect an error (404 Not Found)
		assert.Error(t, err, "GetFileReport should return an error for non-existent hash")
		assert.Nil(t, result, "GetFileReport result should be nil for non-existent hash")
		assert.NotNil(t, resp, "Response should not be nil for API errors")
		assert.NotEqual(t, 200, resp.StatusCode, "Status code should not be 200 for non-existent hash")

		LogTestSuccess(t, "Expected error received: %v", err)
	})
}

// TestAcceptance_Files_GetFileReport_EmptyHash tests validation
func TestAcceptance_Files_GetFileReport_EmptyHash(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "🔒 Validation", "Testing GetFileReport with empty hash")

		result, resp, err := service.GetFileReport(ctx, "")

		// Should fail validation
		assert.Error(t, err, "GetFileReport should return an error for empty hash")
		assert.Nil(t, result, "GetFileReport result should be nil for empty hash")
		assert.Nil(t, resp, "Response should be nil for validation errors (no HTTP call made)")
		assert.Contains(t, err.Error(), "file ID is required", "Error should mention required file ID")

		LogTestSuccess(t, "Validation error received as expected: %v", err)
	})
}

// TestAcceptance_Files_GetUploadURL tests retrieving a file upload URL
func TestAcceptance_Files_GetUploadURL(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "⬆️  Upload", "Testing GetUploadURL")

		result, resp, err := service.GetUploadURL(ctx)
		AssertNoError(t, err, "GetUploadURL should not return an error")
		AssertNotNil(t, result, "GetUploadURL result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate upload URL
		assert.NotEmpty(t, result.Data, "Upload URL should not be empty")
		assert.Contains(t, result.Data, "https://", "Upload URL should be HTTPS")
		assert.Contains(t, result.Data, "virustotal.com", "Upload URL should be VirusTotal domain")

		LogTestSuccess(t, "Upload URL retrieved successfully")
	})
}

// TestAcceptance_Files_GetFileDownloadURL tests retrieving a file download URL
func TestAcceptance_Files_GetFileDownloadURL(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "⬇️  Download", "Testing GetFileDownloadURL with hash: %s", Config.KnownFileHash)

		result, resp, err := service.GetFileDownloadURL(ctx, Config.KnownFileHash)
		
		// File download requires premium/enterprise API key
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "GetFileDownloadURL requires premium API key (403 Forbidden) - test skipped")
			t.Skip("Skipping GetFileDownloadURL test - requires premium/enterprise API key")
			return
		}

		AssertNoError(t, err, "GetFileDownloadURL should not return an error")
		AssertNotNil(t, result, "GetFileDownloadURL result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate download URL
		assert.NotEmpty(t, result.Data, "Download URL should not be empty")
		assert.Contains(t, result.Data, "https://", "Download URL should be HTTPS")

		LogTestSuccess(t, "Download URL retrieved successfully")
	})
}

// TestAcceptance_Files_GetCommentsOnFile tests retrieving comments on a file
func TestAcceptance_Files_GetCommentsOnFile(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "💬 Comments", "Testing GetCommentsOnFile with hash: %s", Config.KnownFileHash)

		// Get comments with limit
		opts := &files.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetCommentsOnFile(ctx, Config.KnownFileHash, opts)
		AssertNoError(t, err, "GetCommentsOnFile should not return an error")
		AssertNotNil(t, result, "GetCommentsOnFile result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Comments data should not be nil")
		assert.IsType(t, []files.RelatedObject{}, result.Data, "Data should be slice of RelatedObject")
		
		commentCount := len(result.Data)
		LogTestSuccess(t, "Retrieved %d comments", commentCount)
		
		// If comments exist, validate structure
		if commentCount > 0 {
			comment := result.Data[0]
			assert.NotEmpty(t, comment.ID, "Comment ID should not be empty")
			assert.Equal(t, "comment", comment.Type, "Comment type should be 'comment'")
			assert.NotNil(t, comment.Attributes, "Comment attributes should not be nil")
			
			// Access attributes from map
			if date, ok := comment.Attributes["date"].(float64); ok {
				assert.Greater(t, date, float64(0), "Comment date should be valid")
				t.Logf("  First comment - Date: %.0f", date)
			}
		}
	})
}

// TestAcceptance_Files_GetObjectsRelatedToFile tests retrieving related objects
func TestAcceptance_Files_GetObjectsRelatedToFile(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "🔗 Relationships", "Testing GetObjectsRelatedToFile (execution_parents) with hash: %s", Config.KnownFileHash)

		// Get execution parents with limit
		opts := &files.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetObjectsRelatedToFile(ctx, Config.KnownFileHash, "execution_parents", opts)
		AssertNoError(t, err, "GetObjectsRelatedToFile should not return an error")
		AssertNotNil(t, result, "GetObjectsRelatedToFile result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Related objects data should not be nil")
		assert.IsType(t, []files.RelatedObject{}, result.Data, "Data should be slice of RelatedObject")
		
		objectCount := len(result.Data)
		LogTestSuccess(t, "Retrieved %d related objects", objectCount)
		
		// If related objects exist, validate structure
		if objectCount > 0 {
			obj := result.Data[0]
			assert.NotEmpty(t, obj.ID, "Object ID should not be empty")
			assert.NotEmpty(t, obj.Type, "Object type should not be empty")
			t.Logf("  First related object - Type: %s, ID: %s", obj.Type, obj.ID)
		}
	})
}

// TestAcceptance_Files_GetObjectDescriptorsRelatedToFile tests retrieving related object descriptors
func TestAcceptance_Files_GetObjectDescriptorsRelatedToFile(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "🔗 Descriptors", "Testing GetObjectDescriptorsRelatedToFile (execution_parents) with hash: %s", Config.KnownFileHash)

		// Get execution parent descriptors with limit
		opts := &files.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetObjectDescriptorsRelatedToFile(ctx, Config.KnownFileHash, "execution_parents", opts)
		AssertNoError(t, err, "GetObjectDescriptorsRelatedToFile should not return an error")
		AssertNotNil(t, result, "GetObjectDescriptorsRelatedToFile result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Descriptors data should not be nil")
		assert.IsType(t, []files.ObjectDescriptor{}, result.Data, "Data should be slice of ObjectDescriptor")
		
		descriptorCount := len(result.Data)
		LogTestSuccess(t, "Retrieved %d object descriptors", descriptorCount)
		
		// If descriptors exist, validate structure
		if descriptorCount > 0 {
			descriptor := result.Data[0]
			assert.NotEmpty(t, descriptor.ID, "Descriptor ID should not be empty")
			assert.NotEmpty(t, descriptor.Type, "Descriptor type should not be empty")
			t.Logf("  First descriptor - Type: %s, ID: %s", descriptor.Type, descriptor.ID)
		}
	})
}

// TestAcceptance_Files_GetVotesOnFile tests retrieving votes on a file
func TestAcceptance_Files_GetVotesOnFile(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogTestStage(t, "🗳️  Votes", "Testing GetVotesOnFile with hash: %s", Config.KnownFileHash)

		// Get votes with limit
		opts := &files.GetVotesOptions{Limit: 10}
		result, resp, err := service.GetVotesOnFile(ctx, Config.KnownFileHash, opts)
		AssertNoError(t, err, "GetVotesOnFile should not return an error")
		AssertNotNil(t, result, "GetVotesOnFile result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Votes data should not be nil")
		assert.IsType(t, []files.Vote{}, result.Data, "Data should be slice of Vote")
		
		voteCount := len(result.Data)
		LogTestSuccess(t, "Retrieved %d votes", voteCount)
		
		// If votes exist, validate structure
		if voteCount > 0 {
			vote := result.Data[0]
			assert.NotEmpty(t, vote.ID, "Vote ID should not be empty")
			assert.Equal(t, "vote", vote.Type, "Vote type should be 'vote'")
			assert.NotNil(t, vote.Attributes, "Vote attributes should not be nil")
			assert.Contains(t, []string{"harmless", "malicious"}, vote.Attributes.Verdict, "Verdict should be harmless or malicious")
			assert.Greater(t, vote.Attributes.Date, int64(0), "Vote date should be valid")
			
			t.Logf("  First vote - Verdict: %s, Date: %d", vote.Attributes.Verdict, vote.Attributes.Date)
		}
	})
}
