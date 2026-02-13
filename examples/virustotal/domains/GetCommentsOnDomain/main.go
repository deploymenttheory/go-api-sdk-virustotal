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

	// Default behavior: Pass nil to automatically fetch all pages
	fmt.Println("=== Get All Comments (Automatic Pagination) ===")
	fmt.Printf("Fetching community comments for domain: %s\n\n", domain)

	response, _, err := vtClient.Domains.GetCommentsOnDomain(ctx, domain, nil)
	if err != nil {
		log.Fatalf("Failed to get comments: %v", err)
	}

	fmt.Printf("Total comments retrieved: %d\n\n", len(response.Data))

	if len(response.Data) == 0 {
		fmt.Println("No comments found for this domain")
		return
	}

	// Display first 10 comments
	displayCount := 10
	if len(response.Data) < displayCount {
		displayCount = len(response.Data)
	}

	fmt.Println("=== Recent Comments ===")
	for i := 0; i < displayCount; i++ {
		comment := response.Data[i]

		fmt.Printf("\n%d. Comment ID: %s\n", i+1, comment.ID)
		fmt.Printf("   Type: %s\n", comment.Type)

		// Extract common comment attributes
		if date, ok := comment.Attributes["date"].(float64); ok {
			commentDate := time.Unix(int64(date), 0)
			fmt.Printf("   Date: %s\n", commentDate.Format("2006-01-02 15:04:05"))
		}

		if text, ok := comment.Attributes["text"].(string); ok {
			fmt.Printf("   Text: %s\n", text)
		}

		if tags, ok := comment.Attributes["tags"].([]any); ok && len(tags) > 0 {
			fmt.Printf("   Tags: %v\n", tags)
		}

		if votes, ok := comment.Attributes["votes"].(map[string]any); ok {
			if harmless, ok := votes["harmless"].(float64); ok {
				fmt.Printf("   Votes - Harmless: %.0f", harmless)
			}
			if malicious, ok := votes["malicious"].(float64); ok {
				fmt.Printf(", Malicious: %.0f\n", malicious)
			} else {
				fmt.Println()
			}
		}
	}

	if len(response.Data) > displayCount {
		fmt.Printf("\n... and %d more comments\n", len(response.Data)-displayCount)
	}

	logger.Info("Comments retrieved successfully",
		zap.String("domain", domain),
		zap.Int("comment_count", len(response.Data)))
}
