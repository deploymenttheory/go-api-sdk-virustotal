package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
)

// This example demonstrates the most basic way to create a VirusTotal client.
//
// IMPORTANT SECURITY NOTE:
// This example shows both environment variable (recommended) and hardcoded
// API key approaches. Always use environment variables in real code!
//
// Use this approach when:
// - You want the simplest possible client setup
// - You don't need custom configuration
// - You're getting started with the SDK
//
// The client uses sensible defaults:
// - 120 second timeout
// - 3 retries with exponential backoff
// - Production-level logging

func main() {
	// OPTION 1: From environment variable (RECOMMENDED)
	// This is the recommended approach - never hardcode API keys!
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

	// OPTION 2: Hardcoded (NOT RECOMMENDED - for demonstration only)
	// Never do this in production! Only for local testing/learning.
	// Hardcoded keys can be accidentally committed to version control.
	// apiKey := "your-api-key-here"  // ⚠️ DON'T DO THIS IN REAL CODE!

	// Create the simplest possible client - just pass the API key
	// NewClient() accepts the API key as a string, regardless of where it comes from
	client, err := virustotal.NewClient(apiKey)
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Use the client to make a simple API call
	ctx := context.Background()
	fileHash := "44d88612fea8a8f36de82e1278abb02f" // EICAR test file

	report, resp, err := client.Files.GetFileReport(ctx, fileHash)
	if err != nil {
		log.Fatalf("Failed to get file report: %v", err)
	}

	// Display results
	fmt.Printf("✓ Client created successfully\n\n")
	fmt.Printf("File Report:\n")
	fmt.Printf("  Hash: %s\n", report.Data.ID)
	fmt.Printf("  Type: %s\n", report.Data.Attributes.Type)
	fmt.Printf("  Size: %d bytes\n", report.Data.Attributes.Size)
	fmt.Printf("  Status Code: %d\n", resp.StatusCode)
	fmt.Printf("  Request Duration: %v\n", resp.Duration)
	fmt.Printf("\nDetection Stats:\n")
	fmt.Printf("  Malicious: %d\n", report.Data.Attributes.LastAnalysisStats.Malicious)
	fmt.Printf("  Suspicious: %d\n", report.Data.Attributes.LastAnalysisStats.Suspicious)
	fmt.Printf("  Harmless: %d\n", report.Data.Attributes.LastAnalysisStats.Harmless)

	fmt.Printf("\n✓ Basic client example completed successfully!\n")
	fmt.Printf("\n💡 Security Reminder:\n")
	fmt.Printf("   Always use environment variables for API keys\n")
	fmt.Printf("   Never hardcode credentials in your source code\n")
	fmt.Printf("   Add .env files to .gitignore\n")
}
