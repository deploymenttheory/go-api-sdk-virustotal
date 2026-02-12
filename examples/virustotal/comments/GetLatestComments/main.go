package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/comments"
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

	// Optional: filter comments by tag
	opts := &comments.GetCommentsOptions{
		Filter: "tag:malware",
		Limit:  10,
	}

	result, _, err := vtClient.Comments.GetLatestComments(ctx, opts)
	if err != nil {
		log.Fatalf("Failed to get latest comments: %v", err)
	}

	fmt.Printf("\n=== Latest Comments ===\n")
	fmt.Printf("Total Comments: %d\n\n", len(result.Data))

	for i, comment := range result.Data {
		fmt.Printf("Comment %d:\n", i+1)
		fmt.Printf("  ID: %s\n", comment.ID)
		fmt.Printf("  Type: %s\n", comment.Type)
		fmt.Printf("  Date: %s\n", time.Unix(comment.Attributes.Date, 0))
		fmt.Printf("  Text: %s\n", comment.Attributes.Text)

		if len(comment.Attributes.Tags) > 0 {
			fmt.Printf("  Tags: %v\n", comment.Attributes.Tags)
		}

		fmt.Printf("  Votes - Positive: %d, Negative: %d, Abuse: %d\n\n",
			comment.Attributes.Votes.Positive,
			comment.Attributes.Votes.Negative,
			comment.Attributes.Votes.Abuse)
	}

	if result.Meta.Cursor != "" {
		fmt.Printf("Pagination cursor available for next page: %s\n", result.Meta.Cursor)
	}

	logger.Info("Latest comments retrieved successfully",
		zap.Int("comment_count", len(result.Data)))
}
