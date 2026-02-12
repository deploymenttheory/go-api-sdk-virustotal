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
	fileID := "44d88612fea8a8f36de82e1278abb02f" // Example MD5 hash (EICAR test file)

	// Supported relationships: contacted_domains, contacted_ips, contacted_urls,
	// dropped_files, bundled_files, execution_parents, itw_urls, pe_resource_parents,
	// overlay_parents, compressed_parents, behaviours, and more
	relationship := "contacted_domains"

	// Default behavior: Pass nil to automatically fetch all pages
	fmt.Println("=== Get All Related Objects (Automatic Pagination) ===")
	fmt.Printf("Fetching all %s for file: %s\n\n", relationship, fileID)

	response, _, err := vtClient.Files.GetObjectsRelatedToFile(ctx, fileID, relationship, nil)
	if err != nil {
		log.Fatalf("Failed to get related objects: %v", err)
	}

	fmt.Printf("Total objects retrieved: %d\n\n", len(response.Data))

	if len(response.Data) == 0 {
		fmt.Printf("No %s found for this file\n", relationship)
		return
	}

	// Display first 10 objects
	displayCount := 10
	if len(response.Data) < displayCount {
		displayCount = len(response.Data)
	}

	for i := 0; i < displayCount; i++ {
		obj := response.Data[i]
		fmt.Printf("%d. Type: %s\n", i+1, obj.Type)
		fmt.Printf("   ID: %s\n", obj.ID)
		if len(obj.Attributes) > 0 {
			fmt.Printf("   Attributes: %v\n", obj.Attributes)
		}
		fmt.Println()
	}

	if len(response.Data) > displayCount {
		fmt.Printf("... and %d more objects\n", len(response.Data)-displayCount)
	}

	logger.Info("Related objects retrieved successfully",
		zap.String("file_id", fileID),
		zap.String("relationship", relationship),
		zap.Int("object_count", len(response.Data)))
}
