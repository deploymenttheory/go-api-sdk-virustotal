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
		client.WithTimeout(30*time.Second),
		client.WithRetryCount(3),
		// client.WithDebug(),
		// client.WithBaseURL("https://www.virustotal.com/api/v3"),
		// client.WithAPIVersion("v3"),
		// client.WithUserAgent("my-app/1.0"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Add a comment to an IP address
	ctx := context.Background()
	ip := "8.8.8.8" // Google DNS

	// Comment text with tags (words starting with # become tags)
	commentText := "This IP is used by Google DNS and is #benign #dns #google"

	result, _, err := vtClient.IPAddresses.AddCommentToIPAddress(ctx, ip, commentText)
	if err != nil {
		log.Fatalf("Failed to add comment to IP address: %v", err)
	}

	// Print the comment information
	fmt.Printf("\n=== Comment Added Successfully ===\n")
	fmt.Printf("IP Address: %s\n", ip)
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
	fmt.Printf("  Total: %d\n", result.Data.Attributes.VotesCount)

	fmt.Printf("\nComment URL: %s\n", result.Data.Links.Self)

	logger.Info("Comment added successfully",
		zap.String("ip", ip),
		zap.String("comment_id", result.Data.ID),
		zap.Strings("tags", result.Data.Attributes.Tags))
}
