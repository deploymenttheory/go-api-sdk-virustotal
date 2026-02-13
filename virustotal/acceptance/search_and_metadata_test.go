package acceptance

import (
	"testing"

	searchandmetadata "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/vt_enterprise/search_and_metadata"
	"github.com/stretchr/testify/assert"
)

// TestAcceptance_Search_BasicSearch tests basic search functionality
func TestAcceptance_Search_BasicSearch(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := searchandmetadata.NewService(Client)

		LogTestStage(t, "🔍 Basic Search", "Testing Search with file hash: %s", Config.KnownFileHash)

		// Search for a known file hash
		result, resp, err := service.Search(ctx, Config.KnownFileHash, nil)
		AssertNoError(t, err, "Search should not return an error")
		AssertNotNil(t, result, "Search result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Search data should not be nil")
		assert.NotEmpty(t, result.Data, "Search should return at least one result")

		// Validate first result
		firstResult := result.Data[0]
		assert.Equal(t, "file", firstResult.Type, "Result type should be 'file'")
		assert.NotEmpty(t, firstResult.ID, "Result ID should not be empty")

		LogTestSuccess(t, "Found %d result(s)", len(result.Data))
		LogTestSuccess(t, "First result - Type: %s, ID: %s", firstResult.Type, firstResult.ID)
	})
}

// TestAcceptance_Search_BasicSearch_WithOptions tests basic search with options
func TestAcceptance_Search_BasicSearch_WithOptions(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := searchandmetadata.NewService(Client)

		LogTestStage(t, "🔍 Basic Search with Options", "Testing Search with limit option")

		opts := &searchandmetadata.SearchOptions{
			Limit: 5,
		}

		result, resp, err := service.Search(ctx, Config.KnownDomain, opts)
		AssertNoError(t, err, "Search should not return an error")
		AssertNotNil(t, result, "Search result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response
		assert.NotNil(t, result.Data, "Search data should not be nil")
		if len(result.Data) > 0 {
			assert.LessOrEqual(t, len(result.Data), 5, "Should return at most 5 results")
			LogTestSuccess(t, "Found %d result(s) with limit of 5", len(result.Data))
		} else {
			LogTestWarning(t, "No results found for domain: %s", Config.KnownDomain)
		}
	})
}

// TestAcceptance_Search_BasicSearch_EmptyQuery tests validation for empty query
func TestAcceptance_Search_BasicSearch_EmptyQuery(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := searchandmetadata.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing Search with empty query")

	result, _, err := service.Search(ctx, "", nil)

	// We expect a validation error
	assert.Error(t, err, "Search should return an error for empty query")
	assert.Nil(t, result, "Search result should be nil for empty query")
	assert.Contains(t, err.Error(), "search query cannot be empty", "Error message should indicate empty query")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}

// TestAcceptance_Search_IntelligenceSearch tests VT Intelligence search (premium feature)
func TestAcceptance_Search_IntelligenceSearch(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := searchandmetadata.NewService(Client)

		LogTestStage(t, "🔬 Intelligence Search", "Testing IntelligenceSearch with type:peexe query")

		// Use a simple query that doesn't require premium (or handle 403 gracefully)
		result, resp, err := service.IntelligenceSearch(ctx, "type:peexe", nil)
		
		// Check if this requires premium privileges
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "IntelligenceSearch requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping IntelligenceSearch test - requires premium/enterprise API key")
		}

		AssertNoError(t, err, "IntelligenceSearch should not return an error")
		AssertNotNil(t, result, "IntelligenceSearch result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Search data should not be nil")
		assert.NotEmpty(t, result.Data, "Search should return at least one result")

		// Validate first result
		firstResult := result.Data[0]
		assert.Equal(t, "file", firstResult.Type, "Result type should be 'file'")
		assert.NotEmpty(t, firstResult.ID, "Result ID should not be empty")

		// Check for context attributes if present
		if firstResult.ContextAttributes != nil {
			LogTestSuccess(t, "Context attributes present in results")
			if firstResult.ContextAttributes.Snippet != "" {
				LogTestSuccess(t, "Snippet ID: %s", firstResult.ContextAttributes.Snippet)
			}
		}

		// Check meta information
		if result.Meta.Cursor != "" {
			LogTestSuccess(t, "Cursor for pagination: %s", result.Meta.Cursor)
		}
		if result.Meta.DaysBack > 0 {
			LogTestSuccess(t, "Search covers %d days back", result.Meta.DaysBack)
		}

		LogTestSuccess(t, "Found %d result(s)", len(result.Data))
	})
}

// TestAcceptance_Search_IntelligenceSearch_WithOptions tests intelligence search with options
func TestAcceptance_Search_IntelligenceSearch_WithOptions(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := searchandmetadata.NewService(Client)

		LogTestStage(t, "🔬 Intelligence Search with Options", "Testing with descriptors_only and order")

		opts := &searchandmetadata.IntelligenceSearchOptions{
			Limit:           10,
			Order:           searchandmetadata.OrderLastSubmissionDateDesc,
			DescriptorsOnly: true,
		}

		result, resp, err := service.IntelligenceSearch(ctx, "size:1mb+", opts)
		
		// Check if this requires premium privileges
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "IntelligenceSearch requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping IntelligenceSearch test - requires premium/enterprise API key")
		}

		AssertNoError(t, err, "IntelligenceSearch should not return an error")
		AssertNotNil(t, result, "IntelligenceSearch result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response
		assert.NotNil(t, result.Data, "Search data should not be nil")
		if len(result.Data) > 0 {
			assert.LessOrEqual(t, len(result.Data), 10, "Should return at most 10 results")
			LogTestSuccess(t, "Found %d result(s) with limit of 10", len(result.Data))
		}

		// With descriptors_only, we should still get type and ID
		if len(result.Data) > 0 {
			firstResult := result.Data[0]
			assert.NotEmpty(t, firstResult.Type, "Result type should not be empty")
			assert.NotEmpty(t, firstResult.ID, "Result ID should not be empty")
			LogTestSuccess(t, "Descriptors returned - Type: %s, ID: %s", firstResult.Type, firstResult.ID)
		}
	})
}

// TestAcceptance_Search_IntelligenceSearch_ContentSearch tests content search (premium feature)
func TestAcceptance_Search_IntelligenceSearch_ContentSearch(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := searchandmetadata.NewService(Client)

		LogTestStage(t, "🔬 Content Search", "Testing IntelligenceSearch with content query")

		// Search for files containing a common string
		result, resp, err := service.IntelligenceSearch(ctx, "content:\"MZ\"", nil)
		
		// Check if this requires premium privileges
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "Content search requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping content search test - requires premium/enterprise API key")
		}

		AssertNoError(t, err, "Content search should not return an error")
		AssertNotNil(t, result, "Content search result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Search data should not be nil")
		if len(result.Data) > 0 {
			firstResult := result.Data[0]
			
			// Content search should include context attributes
			if firstResult.ContextAttributes != nil {
				LogTestSuccess(t, "Context attributes present for content search")
				
				if firstResult.ContextAttributes.Confidence != nil {
					LogTestSuccess(t, "Confidence: %f", *firstResult.ContextAttributes.Confidence)
				}
				
				if firstResult.ContextAttributes.MatchInSubfile != nil {
					LogTestSuccess(t, "Match in subfile: %v", *firstResult.ContextAttributes.MatchInSubfile)
				}
				
				if firstResult.ContextAttributes.Snippet != "" {
					LogTestSuccess(t, "Snippet ID available: %s", firstResult.ContextAttributes.Snippet)
				}
			}
			
			LogTestSuccess(t, "Found %d result(s) with content match", len(result.Data))
		}
	})
}

// TestAcceptance_Search_GetSearchSnippets tests retrieving search snippets (premium feature)
func TestAcceptance_Search_GetSearchSnippets(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := searchandmetadata.NewService(Client)

		LogTestStage(t, "📄 Search Snippets", "Testing GetSearchSnippets")

		// First, try to get a snippet ID from a content search
		searchResult, searchResp, searchErr := service.IntelligenceSearch(ctx, "content:\"This program\"", nil)
		
		// Check if search requires premium
		if searchErr != nil && searchResp != nil && searchResp.StatusCode == 403 {
			LogTestWarning(t, "Content search requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping GetSearchSnippets test - requires premium/enterprise API key")
		}

		if searchErr != nil || len(searchResult.Data) == 0 {
			LogTestWarning(t, "Could not obtain snippet ID from content search - test skipped")
			t.Skip("Skipping GetSearchSnippets test - no snippet ID available")
		}

		// Check if we have a snippet ID
		var snippetID string
		for _, result := range searchResult.Data {
			if result.ContextAttributes != nil && result.ContextAttributes.Snippet != "" {
				snippetID = result.ContextAttributes.Snippet
				break
			}
		}

		if snippetID == "" {
			LogTestWarning(t, "No snippet ID found in search results - test skipped")
			t.Skip("Skipping GetSearchSnippets test - no snippet ID in results")
		}

		LogTestStage(t, "📄 Search Snippets", "Retrieved snippet ID: %s", snippetID)

		// Now test GetSearchSnippets
		result, resp, err := service.GetSearchSnippets(ctx, snippetID)
		
		// Check if this requires premium privileges
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "GetSearchSnippets requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping GetSearchSnippets test - requires premium/enterprise API key")
		}

		AssertNoError(t, err, "GetSearchSnippets should not return an error")
		AssertNotNil(t, result, "GetSearchSnippets result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Snippets data should not be nil")
		assert.NotEmpty(t, result.Data, "Snippets should contain at least one line")

		LogTestSuccess(t, "Retrieved %d snippet line(s)", len(result.Data))
		
		// Log first few lines of snippet
		for i, line := range result.Data {
			if i >= 3 {
				break
			}
			t.Logf("  Snippet line %d: %s", i+1, line)
		}
	})
}

// TestAcceptance_Search_GetSearchSnippets_EmptySnippetID tests validation for empty snippet ID
func TestAcceptance_Search_GetSearchSnippets_EmptySnippetID(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := searchandmetadata.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing GetSearchSnippets with empty snippet ID")

	result, _, err := service.GetSearchSnippets(ctx, "")

	// We expect a validation error
	assert.Error(t, err, "GetSearchSnippets should return an error for empty snippet ID")
	assert.Nil(t, result, "GetSearchSnippets result should be nil for empty snippet ID")
	assert.Contains(t, err.Error(), "snippet ID cannot be empty", "Error message should indicate empty snippet ID")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}

// TestAcceptance_Search_GetMetadata tests retrieving VirusTotal metadata (premium feature)
func TestAcceptance_Search_GetMetadata(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := searchandmetadata.NewService(Client)

		LogTestStage(t, "📊 Metadata", "Testing GetMetadata")

		result, resp, err := service.GetMetadata(ctx)
		
		// Check if this requires premium privileges
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "GetMetadata requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping GetMetadata test - requires premium/enterprise API key")
		}

		AssertNoError(t, err, "GetMetadata should not return an error")
		AssertNotNil(t, result, "GetMetadata result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data.Engines, "Engines map should not be nil")
		assert.NotEmpty(t, result.Data.Engines, "Engines map should contain at least one engine")
		
		assert.NotNil(t, result.Data.Privileges, "Privileges list should not be nil")
		// Note: Privileges might be empty for basic API keys
		
		assert.NotNil(t, result.Data.Relationships, "Relationships map should not be nil")
		assert.NotEmpty(t, result.Data.Relationships, "Relationships map should contain at least one entity type")

		// Log some engines
		engineCount := 0
		for engineName := range result.Data.Engines {
			if engineCount < 5 {
				LogTestSuccess(t, "Engine: %s", engineName)
				engineCount++
			}
		}
		LogTestSuccess(t, "Total engines: %d", len(result.Data.Engines))

		// Log privileges
		if len(result.Data.Privileges) > 0 {
			LogTestSuccess(t, "User privileges: %v", result.Data.Privileges)
		} else {
			LogTestSuccess(t, "No special privileges (basic API key)")
		}

		// Validate some expected relationships
		if fileRels, exists := result.Data.Relationships["file"]; exists {
			assert.NotEmpty(t, fileRels, "File relationships should not be empty")
			LogTestSuccess(t, "File relationships count: %d", len(fileRels))
			
			// Log first few file relationships
			for i, rel := range fileRels {
				if i >= 3 {
					break
				}
				LogTestSuccess(t, "  File relationship: %s - %s", rel.Name, rel.Description)
			}
		}

		if urlRels, exists := result.Data.Relationships["url"]; exists {
			assert.NotEmpty(t, urlRels, "URL relationships should not be empty")
			LogTestSuccess(t, "URL relationships count: %d", len(urlRels))
		}

		if domainRels, exists := result.Data.Relationships["domain"]; exists {
			assert.NotEmpty(t, domainRels, "Domain relationships should not be empty")
			LogTestSuccess(t, "Domain relationships count: %d", len(domainRels))
		}

		LogTestSuccess(t, "Metadata contains %d relationship types", len(result.Data.Relationships))
	})
}

// TestAcceptance_Search_Pagination tests pagination through search results
func TestAcceptance_Search_Pagination(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := searchandmetadata.NewService(Client)

		LogTestStage(t, "📄 Pagination", "Testing Search pagination")

		// First request with small limit
		opts := &searchandmetadata.SearchOptions{
			Limit: 2,
		}

		result, resp, err := service.Search(ctx, Config.KnownFileHash, opts)
		AssertNoError(t, err, "First Search request should not return an error")
		AssertNotNil(t, result, "Search result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		firstPageCount := len(result.Data)
		LogTestSuccess(t, "First page returned %d result(s)", firstPageCount)

		// Check if there's a next cursor
		if result.Links.Next != "" {
			LogTestSuccess(t, "Pagination cursor available: %s", result.Meta.Cursor)
			
			// Note: In a real pagination test, we would make another request with the cursor
			// However, to respect rate limits in acceptance tests, we'll just verify the cursor exists
			assert.NotEmpty(t, result.Meta.Cursor, "Cursor should not be empty when next link is present")
		} else {
			LogTestWarning(t, "No pagination available (all results returned in first page)")
		}
	})
}
