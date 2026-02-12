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
	// Sandbox ID format: {file_sha256}_{sandbox_name}
	sandboxID := "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f_VirusTotal Jujubox"
	relationship := "file" // Supported: file, attack_techniques

	// Get related objects with automatic pagination (pass nil)
	relatedObjects, _, err := vtClient.FileBehaviours.GetObjectsRelatedToFileBehaviour(ctx, sandboxID, relationship, nil)
	if err != nil {
		log.Fatalf("Failed to get related objects: %v", err)
	}

	fmt.Printf("\n=== Objects Related to Behaviour ===\n")
	fmt.Printf("Sandbox ID: %s\n", sandboxID)
	fmt.Printf("Relationship: %s\n", relationship)
	fmt.Printf("Total Objects: %d\n\n", len(relatedObjects.Data))

	for i, obj := range relatedObjects.Data {
		fmt.Printf("Object %d:\n", i+1)
		fmt.Printf("  ID: %s\n", obj.ID)
		fmt.Printf("  Type: %s\n", obj.Type)

		if len(obj.Attributes) > 0 {
			fmt.Printf("  Attributes:\n")
			count := 0
			for key, value := range obj.Attributes {
				if count < 5 {
					fmt.Printf("    %s: %v\n", key, value)
					count++
				}
			}
			if len(obj.Attributes) > 5 {
				fmt.Printf("    ... and %d more attributes\n", len(obj.Attributes)-5)
			}
		}

		fmt.Println()

		if i >= 9 { // Show first 10 objects
			remaining := len(relatedObjects.Data) - 10
			if remaining > 0 {
				fmt.Printf("... and %d more objects\n", remaining)
			}
			break
		}
	}

	logger.Info("Related objects retrieved successfully",
		zap.String("sandbox_id", sandboxID),
		zap.String("relationship", relationship),
		zap.Int("object_count", len(relatedObjects.Data)))
}
