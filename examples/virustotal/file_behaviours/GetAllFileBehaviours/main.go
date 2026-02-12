package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/file_behaviours"
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
	fileID := "44d88612fea8a8f36de82e1278abb02f" // Example MD5 hash (EICAR test file)

	// Option 1: Get all behaviours with automatic pagination (pass nil)
	fmt.Println("\n=== Getting All Behaviour Reports (Automatic Pagination) ===")
	allBehaviours, _, err := vtClient.FileBehaviours.GetAllFileBehaviours(ctx, fileID, nil)
	if err != nil {
		log.Fatalf("Failed to get all file behaviours: %v", err)
	}

	fmt.Printf("File ID: %s\n", fileID)
	fmt.Printf("Total Behaviour Reports: %d\n\n", len(allBehaviours.Data))

	for i, behaviour := range allBehaviours.Data {
		fmt.Printf("Report %d:\n", i+1)
		fmt.Printf("  ID: %s\n", behaviour.ID)
		fmt.Printf("  Type: %s\n", behaviour.Type)

		if behaviour.Attributes.SandboxName != "" {
			fmt.Printf("  Sandbox: %s\n", behaviour.Attributes.SandboxName)
		}

		if len(behaviour.Attributes.Tags) > 0 {
			fmt.Printf("  Tags: %v\n", behaviour.Attributes.Tags)
		}
		fmt.Println()
	}

	// Option 2: Manual pagination with limit
	fmt.Println("\n=== Manual Pagination Example (Limit 10) ===")
	options := &file_behaviours.GetRelatedObjectsOptions{
		Limit: 10,
	}

		pageResult, _, err := vtClient.FileBehaviours.GetAllFileBehaviours(ctx, fileID, options)
	if err != nil {
		log.Fatalf("Failed to get paginated behaviours: %v", err)
	}

	fmt.Printf("Retrieved: %d behaviour reports\n", len(pageResult.Data))
	if pageResult.Meta.Cursor != "" {
		fmt.Printf("Next Page Cursor: %s\n", pageResult.Meta.Cursor)
	}

	logger.Info("File behaviours retrieved successfully",
		zap.String("file_id", fileID),
		zap.Int("total_behaviours", len(allBehaviours.Data)))
}
