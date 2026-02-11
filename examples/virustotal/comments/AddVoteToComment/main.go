package main

import (
	"context"
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
	commentID := "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345"

	// Vote values: positive (useful), negative (not useful), abuse
	// Set one to 1 and others to 0
	positive := 1
	negative := 0
	abuse := 0

	result, err := vtClient.Comments.AddVoteToComment(ctx, commentID, positive, negative, abuse)
	if err != nil {
		log.Fatalf("Failed to add vote: %v", err)
	}

	fmt.Printf("\n=== Vote Added to Comment ===\n")
	fmt.Printf("Comment ID: %s\n\n", commentID)

	fmt.Printf("Vote Recorded:\n")
	fmt.Printf("  Positive: %d\n", result.Data.Positive)
	fmt.Printf("  Negative: %d\n", result.Data.Negative)
	fmt.Printf("  Abuse: %d\n\n", result.Data.Abuse)

	fmt.Printf("Note: Each user can only vote once per comment.\n")
	fmt.Printf("Subsequent votes will update the previous vote.\n")

	logger.Info("Vote added successfully",
		zap.String("comment_id", commentID),
		zap.Int("positive", positive))
}
