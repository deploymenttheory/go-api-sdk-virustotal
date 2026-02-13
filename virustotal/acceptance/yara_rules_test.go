package acceptance

import (
	"testing"

	yararules "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/vt_hunting/yara_rules"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// ListYaraRules Tests
// =============================================================================

// TestAcceptance_YaraRules_ListYaraRules tests listing YARA rules
func TestAcceptance_YaraRules_ListYaraRules(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := yararules.NewService(Client)

		LogTestStage(t, "📋 List YARA Rules", "Listing crowdsourced YARA rules")

		result, resp, err := service.ListYaraRules(ctx, &yararules.ListYaraRulesOptions{
			Limit: 10,
		})

		// Check if this requires premium privileges
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "ListYaraRules requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping ListYaraRules test - requires premium/enterprise API key")
		}

		AssertNoError(t, err, "ListYaraRules should not return an error")
		AssertNotNil(t, result, "ListYaraRules result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Rules data should not be nil")
		if len(result.Data) > 0 {
			LogTestSuccess(t, "Found %d YARA rule(s)", len(result.Data))

			// Validate first rule
			firstRule := result.Data[0]
			assert.Equal(t, "yara_rule", firstRule.Type, "Rule type should be 'yara_rule'")
			assert.NotEmpty(t, firstRule.ID, "Rule ID should not be empty")
			assert.NotEmpty(t, firstRule.Attributes.Name, "Rule name should not be empty")
			assert.NotEmpty(t, firstRule.Attributes.Rule, "Rule content should not be empty")
			assert.GreaterOrEqual(t, firstRule.Attributes.Matches, 0, "Matches should be >= 0")

			LogTestSuccess(t, "First rule: %s (ID: %s)", firstRule.Attributes.Name, firstRule.ID)
			LogTestSuccess(t, "Author: %s, Enabled: %v, Matches: %d",
				firstRule.Attributes.Author,
				firstRule.Attributes.Enabled,
				firstRule.Attributes.Matches)

			if len(firstRule.Attributes.Tags) > 0 {
				LogTestSuccess(t, "Tags: %v", firstRule.Attributes.Tags)
			}
		} else {
			LogTestWarning(t, "No YARA rules found")
		}

		// Validate pagination metadata
		if result.Meta.Cursor != "" {
			LogTestSuccess(t, "Pagination cursor available: %s", result.Meta.Cursor)
		}
	})
}

// TestAcceptance_YaraRules_ListYaraRules_WithFilters tests listing YARA rules with filters
func TestAcceptance_YaraRules_ListYaraRules_WithFilters(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := yararules.NewService(Client)

		LogTestStage(t, "📋 List YARA Rules (Filtered)", "Listing enabled YARA rules ordered by matches")

		result, resp, err := service.ListYaraRules(ctx, &yararules.ListYaraRulesOptions{
			Filter: "enabled:true",
			Order:  "matches-",
			Limit:  5,
		})

		// Check if this requires premium privileges
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "ListYaraRules requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping ListYaraRules test - requires premium/enterprise API key")
		}

		AssertNoError(t, err, "ListYaraRules should not return an error")
		AssertNotNil(t, result, "ListYaraRules result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate that all returned rules are enabled
		for i, rule := range result.Data {
			assert.True(t, rule.Attributes.Enabled, "Rule %d should be enabled", i)
		}

		if len(result.Data) > 0 {
			LogTestSuccess(t, "Found %d enabled YARA rule(s)", len(result.Data))
			LogTestSuccess(t, "Top rule: %s with %d matches",
				result.Data[0].Attributes.Name,
				result.Data[0].Attributes.Matches)
		}
	})
}

// =============================================================================
// GetYaraRule Tests
// =============================================================================

// TestAcceptance_YaraRules_GetYaraRule tests retrieving a specific YARA rule
func TestAcceptance_YaraRules_GetYaraRule(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := yararules.NewService(Client)

		// First, get a list of rules to find a valid rule ID
		LogTestStage(t, "🔍 Get YARA Rule", "Fetching list to find a valid rule ID")

		listResult, listResp, listErr := service.ListYaraRules(ctx, &yararules.ListYaraRulesOptions{
			Limit: 1,
		})

		// Check if this requires premium privileges
		if listErr != nil && listResp != nil && listResp.StatusCode == 403 {
			LogTestWarning(t, "ListYaraRules requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping GetYaraRule test - requires premium/enterprise API key")
		}

		AssertNoError(t, listErr, "ListYaraRules should not return an error")

		if len(listResult.Data) == 0 {
			t.Skip("No YARA rules available to test GetYaraRule")
		}

		ruleID := listResult.Data[0].ID

		LogTestStage(t, "🔍 Get YARA Rule", "Retrieving YARA rule: %s", ruleID)

		result, resp, err := service.GetYaraRule(ctx, ruleID)

		AssertNoError(t, err, "GetYaraRule should not return an error")
		AssertNotNil(t, result, "GetYaraRule result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.Equal(t, "yara_rule", result.Data.Type, "Rule type should be 'yara_rule'")
		assert.Equal(t, ruleID, result.Data.ID, "Rule ID should match")
		assert.NotEmpty(t, result.Data.Attributes.Name, "Rule name should not be empty")
		assert.NotEmpty(t, result.Data.Attributes.Rule, "Rule content should not be empty")
		assert.Greater(t, result.Data.Attributes.CreationDate, int64(0), "Creation date should be valid")

		LogTestSuccess(t, "Rule retrieved: %s", result.Data.Attributes.Name)
		LogTestSuccess(t, "Author: %s, Enabled: %v", result.Data.Attributes.Author, result.Data.Attributes.Enabled)
		LogTestSuccess(t, "Matches: %d, Creation Date: %d", result.Data.Attributes.Matches, result.Data.Attributes.CreationDate)

		// Validate rule content
		assert.Contains(t, result.Data.Attributes.Rule, "rule ", "Rule should contain 'rule' keyword")

		// Validate metadata if present
		if len(result.Data.Attributes.Meta) > 0 {
			LogTestSuccess(t, "Rule has %d metadata entries", len(result.Data.Attributes.Meta))
			for _, meta := range result.Data.Attributes.Meta {
				LogTestSuccess(t, "  - %s: %s", meta.Key, meta.Value)
			}
		}

		// Validate tags if present
		if len(result.Data.Attributes.Tags) > 0 {
			LogTestSuccess(t, "Tags: %v", result.Data.Attributes.Tags)
		}
	})
}

// TestAcceptance_YaraRules_GetYaraRule_EmptyID tests validation for empty ID
func TestAcceptance_YaraRules_GetYaraRule_EmptyID(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := yararules.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing GetYaraRule with empty ID")

	result, _, err := service.GetYaraRule(ctx, "")

	assert.Error(t, err, "GetYaraRule should return an error for empty ID")
	assert.Nil(t, result, "GetYaraRule result should be nil for empty ID")
	assert.Contains(t, err.Error(), "YARA rule ID cannot be empty", "Error message should indicate empty ID")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}

// =============================================================================
// GetObjectsRelatedToYaraRule Tests
// =============================================================================

// TestAcceptance_YaraRules_GetObjectsRelatedToYaraRule tests retrieving files matching a YARA rule
func TestAcceptance_YaraRules_GetObjectsRelatedToYaraRule(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := yararules.NewService(Client)

		// First, get a list of rules with matches to find a valid rule ID
		LogTestStage(t, "🔗 Get Related Objects", "Fetching list to find a rule with matches")

		listResult, listResp, listErr := service.ListYaraRules(ctx, &yararules.ListYaraRulesOptions{
			Filter: "matches:1+",
			Limit:  10,
		})

		// Check if this requires premium privileges
		if listErr != nil && listResp != nil && listResp.StatusCode == 403 {
			LogTestWarning(t, "ListYaraRules requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping GetObjectsRelatedToYaraRule test - requires premium/enterprise API key")
		}

		AssertNoError(t, listErr, "ListYaraRules should not return an error")

		if len(listResult.Data) == 0 {
			t.Skip("No YARA rules with matches available to test GetObjectsRelatedToYaraRule")
		}

		// Find a rule with at least one match
		var ruleID string
		for _, rule := range listResult.Data {
			if rule.Attributes.Matches > 0 {
				ruleID = rule.ID
				break
			}
		}

		if ruleID == "" {
			t.Skip("No YARA rules with matches found")
		}

		LogTestStage(t, "🔗 Get Related Objects", "Retrieving files matching rule: %s", ruleID)

		result, resp, err := service.GetObjectsRelatedToYaraRule(ctx, ruleID, yararules.RelationshipFiles, &yararules.GetRelatedObjectsOptions{
			Limit: 5,
		})

		// Check if this requires premium privileges
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "GetObjectsRelatedToYaraRule requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping GetObjectsRelatedToYaraRule test - requires premium/enterprise API key")
		}

		AssertNoError(t, err, "GetObjectsRelatedToYaraRule should not return an error")
		AssertNotNil(t, result, "GetObjectsRelatedToYaraRule result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Related objects data should not be nil")

		if len(result.Data) > 0 {
			LogTestSuccess(t, "Found %d related file(s)", len(result.Data))

			// Validate first file
			firstFile := result.Data[0]
			assert.Equal(t, "file", firstFile.Type, "Object type should be 'file'")
			assert.NotEmpty(t, firstFile.ID, "File ID should not be empty")

			LogTestSuccess(t, "First file ID: %s", firstFile.ID)

			// Log attributes if available
			if firstFile.Attributes != nil {
				if sha256, ok := firstFile.Attributes["sha256"].(string); ok {
					LogTestSuccess(t, "SHA256: %s", sha256)
				}
				if typeDesc, ok := firstFile.Attributes["type_description"].(string); ok {
					LogTestSuccess(t, "Type: %s", typeDesc)
				}
			}
		} else {
			LogTestWarning(t, "No related files found (rule may have been recently added)")
		}
	})
}

// TestAcceptance_YaraRules_GetObjectsRelatedToYaraRule_InvalidRelationship tests validation for invalid relationship
func TestAcceptance_YaraRules_GetObjectsRelatedToYaraRule_InvalidRelationship(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := yararules.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing GetObjectsRelatedToYaraRule with invalid relationship")

	result, _, err := service.GetObjectsRelatedToYaraRule(ctx, "test-rule-id", "invalid_relationship", nil)

	assert.Error(t, err, "GetObjectsRelatedToYaraRule should return an error for invalid relationship")
	assert.Nil(t, result, "GetObjectsRelatedToYaraRule result should be nil for invalid relationship")
	assert.Contains(t, err.Error(), "invalid relationship", "Error message should indicate invalid relationship")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}

// =============================================================================
// GetObjectDescriptorsRelatedToYaraRule Tests
// =============================================================================

// TestAcceptance_YaraRules_GetObjectDescriptorsRelatedToYaraRule tests retrieving object descriptors
func TestAcceptance_YaraRules_GetObjectDescriptorsRelatedToYaraRule(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := yararules.NewService(Client)

		// First, get a list of rules with matches to find a valid rule ID
		LogTestStage(t, "🔗 Get Object Descriptors", "Fetching list to find a rule with matches")

		listResult, listResp, listErr := service.ListYaraRules(ctx, &yararules.ListYaraRulesOptions{
			Filter: "matches:1+",
			Limit:  10,
		})

		// Check if this requires premium privileges
		if listErr != nil && listResp != nil && listResp.StatusCode == 403 {
			LogTestWarning(t, "ListYaraRules requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping GetObjectDescriptorsRelatedToYaraRule test - requires premium/enterprise API key")
		}

		AssertNoError(t, listErr, "ListYaraRules should not return an error")

		if len(listResult.Data) == 0 {
			t.Skip("No YARA rules with matches available to test GetObjectDescriptorsRelatedToYaraRule")
		}

		// Find a rule with at least one match
		var ruleID string
		for _, rule := range listResult.Data {
			if rule.Attributes.Matches > 0 {
				ruleID = rule.ID
				break
			}
		}

		if ruleID == "" {
			t.Skip("No YARA rules with matches found")
		}

		LogTestStage(t, "🔗 Get Object Descriptors", "Retrieving descriptors for rule: %s", ruleID)

		result, resp, err := service.GetObjectDescriptorsRelatedToYaraRule(ctx, ruleID, yararules.RelationshipFiles, &yararules.GetRelatedObjectsOptions{
			Limit: 5,
		})

		// Check if this requires premium privileges
		if err != nil && resp != nil && resp.StatusCode == 403 {
			LogTestWarning(t, "GetObjectDescriptorsRelatedToYaraRule requires premium/enterprise API key (403 Forbidden) - test skipped")
			t.Skip("Skipping GetObjectDescriptorsRelatedToYaraRule test - requires premium/enterprise API key")
		}

		AssertNoError(t, err, "GetObjectDescriptorsRelatedToYaraRule should not return an error")
		AssertNotNil(t, result, "GetObjectDescriptorsRelatedToYaraRule result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Object descriptors data should not be nil")

		if len(result.Data) > 0 {
			LogTestSuccess(t, "Found %d object descriptor(s)", len(result.Data))

			// Validate first descriptor
			firstDescriptor := result.Data[0]
			assert.Equal(t, "file", firstDescriptor.Type, "Descriptor type should be 'file'")
			assert.NotEmpty(t, firstDescriptor.ID, "Descriptor ID should not be empty")

			LogTestSuccess(t, "First descriptor ID: %s", firstDescriptor.ID)

			// Log context attributes if available
			if len(firstDescriptor.ContextAttributes) > 0 {
				LogTestSuccess(t, "Context attributes: %v", firstDescriptor.ContextAttributes)
			}
		} else {
			LogTestWarning(t, "No object descriptors found (rule may have been recently added)")
		}
	})
}

// TestAcceptance_YaraRules_GetObjectDescriptorsRelatedToYaraRule_EmptyID tests validation for empty ID
func TestAcceptance_YaraRules_GetObjectDescriptorsRelatedToYaraRule_EmptyID(t *testing.T) {
	RequireClient(t)

	ctx, cancel := NewContext()
	defer cancel()

	service := yararules.NewService(Client)

	LogTestStage(t, "❌ Validation Test", "Testing GetObjectDescriptorsRelatedToYaraRule with empty ID")

	result, _, err := service.GetObjectDescriptorsRelatedToYaraRule(ctx, "", yararules.RelationshipFiles, nil)

	assert.Error(t, err, "GetObjectDescriptorsRelatedToYaraRule should return an error for empty ID")
	assert.Nil(t, result, "GetObjectDescriptorsRelatedToYaraRule result should be nil for empty ID")
	assert.Contains(t, err.Error(), "YARA rule ID cannot be empty", "Error message should indicate empty ID")

	LogTestSuccess(t, "Expected validation error received: %v", err)
}
