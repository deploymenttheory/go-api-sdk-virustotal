package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	virustotal "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
)

func main() {
	// Initialize the VirusTotal client
	client, err := virustotal.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Analysis ID (obtained from file/URL submission)
	analysisID := os.Getenv("ANALYSIS_ID")
	if analysisID == "" {
		log.Fatal("ANALYSIS_ID environment variable is required")
	}

	// Get the analysis
	ctx := context.Background()
	analysis, _, err := client.Analyses.GetAnalysis(ctx, analysisID)
	if err != nil {
		log.Fatalf("Failed to get analysis: %v", err)
	}

	// Pretty print the result
	jsonData, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println("Analysis Details:")
	fmt.Println(string(jsonData))

	// Print summary
	fmt.Printf("\nAnalysis Summary:\n")
	fmt.Printf("  ID: %s\n", analysis.Data.ID)
	fmt.Printf("  Status: %s\n", analysis.Data.Attributes.Status)
	fmt.Printf("  Malicious: %d\n", analysis.Data.Attributes.Stats.Malicious)
	fmt.Printf("  Suspicious: %d\n", analysis.Data.Attributes.Stats.Suspicious)
	fmt.Printf("  Undetected: %d\n", analysis.Data.Attributes.Stats.Undetected)
	fmt.Printf("  Harmless: %d\n", analysis.Data.Attributes.Stats.Harmless)
}
