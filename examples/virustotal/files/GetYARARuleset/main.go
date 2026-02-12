package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"go.uber.org/zap"
)

func main() {

	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")

	if apiKey == "" {
		log.Fatal("VIRUSTOTAL_API_KEY environment variable must be set")
	}

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	vtClient, err := virustotal.NewClient(apiKey,
		client.WithLogger(logger),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// YARA ruleset ID (obtained from file analysis results)
	// Example: get this ID from a file report's crowdsourced_yara_results
	yaraRulesetID := "example-yara-ruleset-id"

	result, _, err := vtClient.Files.GetYARARuleset(ctx, yaraRulesetID)
	if err != nil {
		log.Fatalf("Failed to get YARA ruleset: %v", err)
	}

	// Print YARA ruleset information
	fmt.Printf("\n=== YARA Ruleset Information ===\n")
	fmt.Printf("Ruleset ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n\n", result.Data.Type)

	// Print attributes as JSON for better readability
	attrs, err := json.MarshalIndent(result.Data.Attributes, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal attributes: %v", err)
	}

	fmt.Printf("Attributes:\n%s\n", string(attrs))

	if result.Data.Links.Self != "" {
		fmt.Printf("\nRuleset URL: %s\n", result.Data.Links.Self)
	}

	logger.Info("YARA ruleset retrieved successfully",
		zap.String("ruleset_id", yaraRulesetID))
}
