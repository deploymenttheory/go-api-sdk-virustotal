package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	virustotal "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
)

func main() {
	// Initialize the VirusTotal client
	client, err := virustotal.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Attack tactic ID (e.g., TA0004 for Privilege Escalation)
	// See MITRE ATT&CK framework: https://attack.mitre.org/tactics/enterprise/
	tacticID := "TA0004"

	// Get the attack tactic
	ctx := context.Background()
	tactic, _, err := client.AttackTactics.GetAttackTactic(ctx, tacticID)
	if err != nil {
		log.Fatalf("Failed to get attack tactic: %v", err)
	}

	// Pretty print the result
	jsonData, err := json.MarshalIndent(tactic, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println("Attack Tactic Details:")
	fmt.Println(string(jsonData))

	// Print summary
	fmt.Printf("\nAttack Tactic Summary:\n")
	fmt.Printf("  ID: %s\n", tactic.Data.ID)
	fmt.Printf("  Name: %s\n", tactic.Data.Attributes.Name)
	fmt.Printf("  Description: %s\n", tactic.Data.Attributes.Description)
	fmt.Printf("  STIX ID: %s\n", tactic.Data.Attributes.StixID)
	fmt.Printf("  MITRE Link: %s\n", tactic.Data.Attributes.Link)
	fmt.Printf("  Created: %s\n", time.Unix(tactic.Data.Attributes.CreationDate, 0).Format(time.RFC3339))
	fmt.Printf("  Last Modified: %s\n", time.Unix(tactic.Data.Attributes.LastModificationDate, 0).Format(time.RFC3339))
}
