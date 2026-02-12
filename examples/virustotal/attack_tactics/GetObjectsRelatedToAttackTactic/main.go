package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	virustotal "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/attack_tactics"
)

func main() {
	// Initialize the VirusTotal client
	client, err := virustotal.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Attack tactic ID (e.g., TA0004 for Privilege Escalation)
	tacticID := "TA0004"

	// Get attack techniques related to this tactic
	ctx := context.Background()
	relatedObjects, _, err := client.AttackTactics.GetObjectsRelatedToAttackTactic(
		ctx,
		tacticID,
		attack_tactics.RelationshipAttackTechniques,
		&attack_tactics.GetRelatedObjectsOptions{
			Limit: 10, // Get first 10 related techniques
		},
	)
	if err != nil {
		log.Fatalf("Failed to get related objects: %v", err)
	}

	// Pretty print the result
	jsonData, err := json.MarshalIndent(relatedObjects, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println("Related Attack Techniques:")
	fmt.Println(string(jsonData))

	// Print summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Total techniques: %d\n", relatedObjects.Meta.Count)
	fmt.Printf("\nTechniques:\n")
	for i, obj := range relatedObjects.Data {
		fmt.Printf("  %d. Type: %s, ID: %s\n", i+1, obj.Type, obj.ID)
		if obj.Attributes != nil {
			if name, ok := obj.Attributes["name"].(string); ok {
				fmt.Printf("     Name: %s\n", name)
			}
			if description, ok := obj.Attributes["description"].(string); ok {
				fmt.Printf("     Description: %s\n", description[:100]+"...")
			}
		}
	}

	// Check for more results
	if relatedObjects.Links.Next != "" {
		fmt.Printf("\nMore results available. Use cursor for pagination.\n")
	}
}
