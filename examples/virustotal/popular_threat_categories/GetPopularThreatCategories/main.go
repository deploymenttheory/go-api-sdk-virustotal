package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	virustotal "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
)

func main() {
	// Initialize the VirusTotal client
	client, err := virustotal.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Get popular threat categories
	ctx := context.Background()
	categories, err := client.PopularThreatCategories.GetPopularThreatCategories(ctx)
	if err != nil {
		log.Fatalf("Failed to get popular threat categories: %v", err)
	}

	// Pretty print the result
	jsonData, err := json.MarshalIndent(categories, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println("Popular Threat Categories:")
	fmt.Println(string(jsonData))

	// Print summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Total categories: %d\n\n", len(categories.Data))
	fmt.Printf("Categories:\n")
	for i, category := range categories.Data {
		fmt.Printf("  %d. %s (%s)\n", i+1, category.Attributes.Name, category.ID)
	}
}
