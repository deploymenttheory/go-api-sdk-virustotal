package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	virustotal "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/analyses"
)

func main() {
	// Check API key from environment
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

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

	// Get related object descriptors (item - the file or URL that was analyzed)
	ctx := context.Background()
	descriptors, _, err := client.Analyses.GetObjectDescriptorsRelatedToAnalysis(
		ctx,
		analysisID,
		analyses.RelationshipItem,
		nil, // nil for automatic pagination (all pages)
	)
	if err != nil {
		log.Fatalf("Failed to get object descriptors: %v", err)
	}

	// Pretty print the result
	jsonData, err := json.MarshalIndent(descriptors, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println("Object Descriptors (Item):")
	fmt.Println(string(jsonData))

	// Print summary
	fmt.Printf("\nTotal object descriptors: %d\n", len(descriptors.Data))
	for i, desc := range descriptors.Data {
		fmt.Printf("  [%d] Type: %s, ID: %s\n", i+1, desc.Type, desc.ID)
	}
}
