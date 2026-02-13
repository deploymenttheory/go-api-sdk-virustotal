package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
)

// This example demonstrates creating a client using environment variables.
//
// Use this approach when:
// - You want to follow 12-factor app principles
// - Your API key is stored in environment variables
// - You want the convenience of automatic environment variable handling
// - You need to support optional environment-based configuration
//
// Supported environment variables:
// - VT_API_KEY (required): Your VirusTotal API key
// - VIRUSTOTAL_BASE_URL (optional): Custom base URL for the API

func main() {
	// Check API key from environment
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

	// Create client from environment variables
	// This automatically reads VT_API_KEY and optional VIRUSTOTAL_BASE_URL
	client, err := virustotal.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Use the client to make an API call
	ctx := context.Background()
	domain := "example.com"

	report, resp, err := client.Domains.GetDomainReport(ctx, domain)
	if err != nil {
		log.Fatalf("Failed to get domain report: %v", err)
	}

	// Display results
	fmt.Printf("✓ Client created from environment variables\n\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  API Key: %s...%s (redacted)\n", apiKey[:4], apiKey[len(apiKey)-4:])
	if baseURL := os.Getenv("VIRUSTOTAL_BASE_URL"); baseURL != "" {
		fmt.Printf("  Custom Base URL: %s\n", baseURL)
	} else {
		fmt.Printf("  Base URL: https://www.virustotal.com/api/v3 (default)\n")
	}

	fmt.Printf("\nDomain Report:\n")
	fmt.Printf("  Domain: %s\n", report.Data.ID)
	fmt.Printf("  Reputation: %d\n", report.Data.Attributes.Reputation)
	fmt.Printf("  Status Code: %d\n", resp.StatusCode)
	fmt.Printf("  Request Duration: %v\n", resp.Duration)

	if report.Data.Attributes.LastAnalysisStats.Malicious > 0 {
		fmt.Printf("\n⚠️  Warning: Domain has malicious detections!\n")
		fmt.Printf("  Malicious: %d\n", report.Data.Attributes.LastAnalysisStats.Malicious)
	} else {
		fmt.Printf("\n✓ Domain appears clean\n")
		fmt.Printf("  Harmless: %d\n", report.Data.Attributes.LastAnalysisStats.Harmless)
	}

	fmt.Printf("\n✓ Environment-based client example completed successfully!\n")
}
