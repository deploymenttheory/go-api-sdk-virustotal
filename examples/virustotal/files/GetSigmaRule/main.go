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

	// Sigma rule ID (obtained from file analysis results)
	// Example: get this ID from a file report's crowdsourced_sigma_analysis_results
	sigmaRuleID := "example-sigma-rule-id"

	result, _, err := vtClient.Files.GetSigmaRule(ctx, sigmaRuleID)
	if err != nil {
		log.Fatalf("Failed to get Sigma rule: %v", err)
	}

	// Print Sigma rule information
	fmt.Printf("\n=== Sigma Rule Information ===\n")
	fmt.Printf("Rule ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n\n", result.Data.Type)

	// Print attributes as JSON for better readability
	attrs, err := json.MarshalIndent(result.Data.Attributes, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal attributes: %v", err)
	}

	fmt.Printf("Attributes:\n%s\n", string(attrs))

	if result.Data.Links.Self != "" {
		fmt.Printf("\nRule URL: %s\n", result.Data.Links.Self)
	}

	logger.Info("Sigma rule retrieved successfully",
		zap.String("rule_id", sigmaRuleID))
}
