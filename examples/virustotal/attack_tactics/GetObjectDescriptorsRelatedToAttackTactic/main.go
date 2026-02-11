package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	virustotal "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/attack_tactics"
)

func main() {
	// Initialize the VirusTotal client
	client, err := virustotal.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Attack tactic ID (e.g., TA0004 for Privilege Escalation)
	tacticID := "TA0004"

	// Get attack technique descriptors (lightweight, just type and ID)
	// This is more efficient when you only need the identifiers
	ctx := context.Background()
	descriptors, err := client.AttackTactics.GetObjectDescriptorsRelatedToAttackTactic(
		ctx,
		tacticID,
		attack_tactics.RelationshipAttackTechniques,
		&attack_tactics.GetRelatedObjectsOptions{
			Limit: 20, // Get first 20 technique IDs
		},
	)
	if err != nil {
		log.Fatalf("Failed to get object descriptors: %v", err)
	}

	// Pretty print the result
	jsonData, err := json.MarshalIndent(descriptors, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println("Related Attack Technique Descriptors:")
	fmt.Println(string(jsonData))

	// Print summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Total technique descriptors: %d\n", descriptors.Meta.Count)
	fmt.Printf("\nTechnique IDs:\n")
	for i, descriptor := range descriptors.Data {
		fmt.Printf("  %d. %s (%s)\n", i+1, descriptor.ID, descriptor.Type)
	}

	// Note: Descriptors only contain type and ID
	// Use GetObjectsRelatedToAttackTactic if you need full attributes
	fmt.Printf("\nNote: These are lightweight descriptors.\n")
	fmt.Printf("Use GetObjectsRelatedToAttackTactic to get full technique details.\n")

	// Check for more results
	if descriptors.Links.Next != "" {
		fmt.Printf("\nMore results available. Use cursor for pagination.\n")
	}
}
