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
	// Retrieve API key from environment variable
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")

	if apiKey == "" {
		log.Fatal("VIRUSTOTAL_API_KEY environment variable must be set")
	}

	// Create logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	// Create VirusTotal API client
	vtClient, err := virustotal.NewClient(apiKey,
		client.WithLogger(logger),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	fileID := "44d88612fea8a8f36de82e1278abb02f" // Example MD5 hash (EICAR test file)

	// Default behavior: Pass nil to automatically fetch all pages
	fmt.Println("=== Get All Votes (Automatic Pagination) ===")
	fmt.Printf("Fetching community votes for file: %s\n\n", fileID)

	response, err := vtClient.Files.GetVotesOnFile(ctx, fileID, nil)
	if err != nil {
		log.Fatalf("Failed to get votes: %v", err)
	}

	fmt.Printf("Total votes retrieved: %d\n\n", len(response.Data))

	if len(response.Data) == 0 {
		fmt.Println("No votes found for this file")
		return
	}

	// Count votes by verdict
	harmlessCount := 0
	maliciousCount := 0
	totalValue := 0

	for _, vote := range response.Data {
		switch vote.Attributes.Verdict {
		case "harmless":
			harmlessCount++
		case "malicious":
			maliciousCount++
		}
		totalValue += vote.Attributes.Value
	}

	fmt.Println("=== Vote Summary ===")
	fmt.Printf("Harmless votes: %d\n", harmlessCount)
	fmt.Printf("Malicious votes: %d\n", maliciousCount)
	fmt.Printf("Total vote value: %d\n\n", totalValue)

	if totalValue > 0 {
		fmt.Println("Community verdict: HARMLESS ✓")
	} else if totalValue < 0 {
		fmt.Println("Community verdict: MALICIOUS ✗")
	} else {
		fmt.Println("Community verdict: NEUTRAL")
	}

	// Display first 10 votes
	fmt.Println("\n=== Recent Votes ===")
	displayCount := 10
	if len(response.Data) < displayCount {
		displayCount = len(response.Data)
	}

	for i := 0; i < displayCount; i++ {
		vote := response.Data[i]
		voteDate := time.Unix(vote.Attributes.Date, 0)

		verdictIcon := "✓"
		if vote.Attributes.Verdict == "malicious" {
			verdictIcon = "✗"
		}

		fmt.Printf("%d. %s %s (value: %d) - %s\n",
			i+1,
			verdictIcon,
			vote.Attributes.Verdict,
			vote.Attributes.Value,
			voteDate.Format("2006-01-02 15:04:05"),
		)
	}

	if len(response.Data) > displayCount {
		fmt.Printf("\n... and %d more votes\n", len(response.Data)-displayCount)
	}

	logger.Info("Votes retrieved successfully",
		zap.String("file_id", fileID),
		zap.Int("vote_count", len(response.Data)),
		zap.Int("total_value", totalValue))
}
