package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

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
	domain := "example.com" // Example domain

	// Add a vote to the domain
	verdict := "harmless" // Can be: "harmless" or "malicious"

	fmt.Printf("Adding vote to domain: %s\n", domain)
	fmt.Printf("Verdict: %s\n\n", verdict)

	result, _, err := vtClient.Domains.AddVoteToDomain(ctx, domain, verdict)
	if err != nil {
		log.Fatalf("Failed to add vote: %v", err)
	}

	// Print vote confirmation
	fmt.Println("=== Vote Added Successfully ===")
	fmt.Printf("Vote ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n", result.Data.Type)
	fmt.Printf("Verdict: %s\n", result.Data.Attributes.Verdict)
	fmt.Printf("Value: %d\n", result.Data.Attributes.Value)
	fmt.Printf("Date: %s\n", time.Unix(result.Data.Attributes.Date, 0).Format("2006-01-02 15:04:05"))

	if result.Data.Links.Self != "" {
		fmt.Printf("Link: %s\n", result.Data.Links.Self)
	}

	fmt.Println("\n=== Vote Values ===")
	fmt.Println("Harmless vote = +1")
	fmt.Println("Malicious vote = -1")

	logger.Info("Vote added successfully",
		zap.String("domain", domain),
		zap.String("vote_id", result.Data.ID),
		zap.String("verdict", verdict))
}
