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

	apiKey := os.Getenv("VT_API_KEY")

	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	vtClient, err := virustotal.NewClientFromEnv(
		client.WithLogger(logger),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Add a comment to a domain
	ctx := context.Background()
	domain := "example.com" // Example domain

	// Comment text with tags (words starting with # become tags)
	commentText := "This is a legitimate example domain used for documentation #benign #example #documentation"

	result, _, err := vtClient.Domains.AddCommentToDomain(ctx, domain, commentText)
	if err != nil {
		log.Fatalf("Failed to add comment to domain: %v", err)
	}

	// Print the comment information
	fmt.Printf("\n=== Comment Added Successfully ===\n")
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Comment ID: %s\n", result.Data.ID)
	fmt.Printf("Comment Type: %s\n", result.Data.Type)
	fmt.Printf("Comment Text: %s\n", result.Data.Attributes.Text)
	fmt.Printf("Date: %s\n", time.Unix(result.Data.Attributes.Date, 0))

	if len(result.Data.Attributes.Tags) > 0 {
		fmt.Printf("\nExtracted Tags:\n")
		for _, tag := range result.Data.Attributes.Tags {
			fmt.Printf("  - %s\n", tag)
		}
	}

	fmt.Printf("\nVotes:\n")
	fmt.Printf("  Harmless: %d\n", result.Data.Attributes.Votes.Harmless)
	fmt.Printf("  Malicious: %d\n", result.Data.Attributes.Votes.Malicious)

	fmt.Printf("\nComment URL: %s\n", result.Data.Links.Self)

	logger.Info("Comment added successfully",
		zap.String("domain", domain),
		zap.String("comment_id", result.Data.ID),
		zap.Strings("tags", result.Data.Attributes.Tags))
}
