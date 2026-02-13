package acceptance

import (
	"testing"

	ipaddresses "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/ip_addresses"
	"github.com/stretchr/testify/assert"
)

// TestAcceptance_IPAddresses_GetIPAddressReport tests retrieving IP address information
func TestAcceptance_IPAddresses_GetIPAddressReport(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := ipaddresses.NewService(Client)

		LogTestStage(t, "🌍 IP Address", "Testing GetIPAddressReport with IP: %s", Config.KnownIPAddress)

		result, resp, err := service.GetIPAddressReport(ctx, Config.KnownIPAddress, nil)
		AssertNoError(t, err, "GetIPAddressReport should not return an error")
		AssertNotNil(t, result, "GetIPAddressReport result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")
		assert.NotNil(t, resp.Headers, "Response headers should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "IP address data should not be nil")
		assert.Equal(t, "ip_address", result.Data.Type, "Response type should be 'ip_address'")
		assert.Equal(t, Config.KnownIPAddress, result.Data.ID, "IP address should match requested IP")
		assert.NotNil(t, result.Data.Attributes, "IP address attributes should not be nil")

		// Validate IP attributes
		attrs := result.Data.Attributes
		assert.NotNil(t, attrs.LastAnalysisStats, "Last analysis stats should not be nil")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Harmless, 0, "Harmless count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Malicious, 0, "Malicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Suspicious, 0, "Suspicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Undetected, 0, "Undetected count should be >= 0")
		
		// Validate timestamps
		assert.Greater(t, attrs.LastAnalysisDate, int64(0), "Last analysis date should be valid")
		assert.Greater(t, attrs.LastModificationDate, int64(0), "Last modification date should be valid")
		
		// Validate reputation
		assert.NotEqual(t, 0, attrs.Reputation, "Reputation should be set")
		
		// Google DNS (8.8.8.8) should have network and country info
		assert.NotEmpty(t, attrs.Network, "Network should not be empty for known IP")
		assert.NotEmpty(t, attrs.Country, "Country should not be empty for known IP")
		assert.NotEmpty(t, attrs.ASOwner, "AS owner should not be empty for known IP")
		assert.Greater(t, attrs.ASN, 0, "ASN should be greater than 0")

		LogResponse(t, "IP Address: %s", Config.KnownIPAddress)
		LogResponse(t, "Reputation: %d", attrs.Reputation)
		LogResponse(t, "Network: %s", attrs.Network)
		LogResponse(t, "Country: %s", attrs.Country)
		LogResponse(t, "AS Owner: %s", attrs.ASOwner)
		LogResponse(t, "ASN: %d", attrs.ASN)
		LogResponse(t, "Last Analysis Date: %d", attrs.LastAnalysisDate)
		LogResponse(t, "Analysis Stats - Malicious: %d, Suspicious: %d, Harmless: %d, Undetected: %d",
			attrs.LastAnalysisStats.Malicious,
			attrs.LastAnalysisStats.Suspicious,
			attrs.LastAnalysisStats.Harmless,
			attrs.LastAnalysisStats.Undetected)
	})
}

// TestAcceptance_IPAddresses_GetIPAddressReport_InvalidIP tests error handling
func TestAcceptance_IPAddresses_GetIPAddressReport_InvalidIP(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := ipaddresses.NewService(Client)

		LogTestStage(t, "❌ Error Test", "Testing GetIPAddressReport with invalid IP")

		// Use an invalid IP address format
		result, resp, err := service.GetIPAddressReport(ctx, "999.999.999.999", nil)

		// We expect an error for an invalid IP
		assert.Error(t, err, "GetIPAddressReport should return an error for invalid IP")
		assert.Nil(t, result, "GetIPAddressReport result should be nil for invalid IP")
		assert.NotNil(t, resp, "Response should not be nil for API errors")
		assert.NotEqual(t, 200, resp.StatusCode, "Status code should not be 200 for invalid IP")

		LogTestSuccess(t, "Expected error received: %v", err)
	})
}

// TestAcceptance_IPAddresses_GetIPAddressReport_EmptyIP tests validation
func TestAcceptance_IPAddresses_GetIPAddressReport_EmptyIP(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := ipaddresses.NewService(Client)

		LogTestStage(t, "🔒 Validation", "Testing GetIPAddressReport with empty IP")

		result, resp, err := service.GetIPAddressReport(ctx, "", nil)

		// Should fail validation
		assert.Error(t, err, "GetIPAddressReport should return an error for empty IP")
		assert.Nil(t, result, "GetIPAddressReport result should be nil for empty IP")
		assert.Nil(t, resp, "Response should be nil for validation errors (no HTTP call made)")
		assert.Contains(t, err.Error(), "ip address is required", "Error should mention required IP")

		LogTestSuccess(t, "Validation error received as expected: %v", err)
	})
}

// TestAcceptance_IPAddresses_GetObjectsRelatedToIPAddress tests retrieving related objects (resolutions)
func TestAcceptance_IPAddresses_GetObjectsRelatedToIPAddress(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := ipaddresses.NewService(Client)

		LogTestStage(t, "🔗 Relationships", "Testing GetObjectsRelatedToIPAddress (resolutions) with IP: %s", Config.KnownIPAddress)

		// Get DNS resolutions with limit
		opts := &ipaddresses.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetObjectsRelatedToIPAddress(ctx, Config.KnownIPAddress, "resolutions", opts)
		AssertNoError(t, err, "GetObjectsRelatedToIPAddress should not return an error")
		AssertNotNil(t, result, "GetObjectsRelatedToIPAddress result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Resolutions data should not be nil")
		assert.IsType(t, []ipaddresses.RelatedObject{}, result.Data, "Data should be slice of RelatedObject")
		
		resolutionCount := len(result.Data)
		LogTestSuccess(t, "Retrieved %d DNS resolutions", resolutionCount)
		
		// For Google DNS (8.8.8.8), expect DNS resolutions to exist
		if Config.KnownIPAddress == "8.8.8.8" {
			assert.Greater(t, resolutionCount, 0, "Well-known IP should have DNS resolutions")
			
			if resolutionCount > 0 {
				resolution := result.Data[0]
				assert.NotEmpty(t, resolution.ID, "Resolution ID should not be empty")
				assert.Equal(t, "resolution", resolution.Type, "Resolution type should be 'resolution'")
				LogResponse(t, "First resolution ID: %s", resolution.ID)
			}
		}
	})
}

// TestAcceptance_IPAddresses_GetObjectDescriptorsRelatedToIPAddress tests retrieving related object descriptors
func TestAcceptance_IPAddresses_GetObjectDescriptorsRelatedToIPAddress(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := ipaddresses.NewService(Client)

		LogTestStage(t, "🔗 Descriptors", "Testing GetObjectDescriptorsRelatedToIPAddress (resolutions) with IP: %s", Config.KnownIPAddress)

		// Get DNS resolution descriptors with limit
		opts := &ipaddresses.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetObjectDescriptorsRelatedToIPAddress(ctx, Config.KnownIPAddress, "resolutions", opts)
		AssertNoError(t, err, "GetObjectDescriptorsRelatedToIPAddress should not return an error")
		AssertNotNil(t, result, "GetObjectDescriptorsRelatedToIPAddress result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Descriptors data should not be nil")
		assert.IsType(t, []ipaddresses.ObjectDescriptor{}, result.Data, "Data should be slice of ObjectDescriptor")
		
		descriptorCount := len(result.Data)
		LogTestSuccess(t, "Retrieved %d object descriptors", descriptorCount)
		
		// For Google DNS (8.8.8.8), expect descriptors to exist
		if Config.KnownIPAddress == "8.8.8.8" && descriptorCount > 0 {
			descriptor := result.Data[0]
			assert.NotEmpty(t, descriptor.ID, "Descriptor ID should not be empty")
			assert.Equal(t, "resolution", descriptor.Type, "Descriptor type should be 'resolution'")
			LogResponse(t, "First descriptor - Type: %s, ID: %s", descriptor.Type, descriptor.ID)
		}
	})
}

// TestAcceptance_IPAddresses_GetVotesOnIPAddress tests retrieving votes on an IP address
func TestAcceptance_IPAddresses_GetVotesOnIPAddress(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := ipaddresses.NewService(Client)

		LogTestStage(t, "🗳️  Votes", "Testing GetVotesOnIPAddress with IP: %s", Config.KnownIPAddress)

		// Get votes with limit
		opts := &ipaddresses.GetVotesOptions{Limit: 10}
		result, resp, err := service.GetVotesOnIPAddress(ctx, Config.KnownIPAddress, opts)
		AssertNoError(t, err, "GetVotesOnIPAddress should not return an error")
		AssertNotNil(t, result, "GetVotesOnIPAddress result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Votes data should not be nil")
		assert.IsType(t, []ipaddresses.Vote{}, result.Data, "Data should be slice of Vote")
		
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
			
			LogResponse(t, "First vote - Verdict: %s, Date: %d", vote.Attributes.Verdict, vote.Attributes.Date)
		}
	})
}
