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

	ctx := context.Background()
	// Sandbox ID format: {file_sha256}_{sandbox_name}
	sandboxID := "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f_VirusTotal Jujubox"
	relationship := "attack_techniques" // Supported: file, attack_techniques

	// Get object descriptors with automatic pagination (pass nil)
	descriptors, _, err := vtClient.FileBehaviours.GetObjectDescriptorsForFileBehaviour(ctx, sandboxID, relationship, nil)
	if err != nil {
		log.Fatalf("Failed to get object descriptors: %v", err)
	}

	fmt.Printf("\n=== Object Descriptors for Behaviour ===\n")
	fmt.Printf("Sandbox ID: %s\n", sandboxID)
	fmt.Printf("Relationship: %s\n", relationship)
	fmt.Printf("Total Descriptors: %d\n\n", len(descriptors.Data))

	for i, desc := range descriptors.Data {
		fmt.Printf("Descriptor %d:\n", i+1)
		fmt.Printf("  ID: %s\n", desc.ID)
		fmt.Printf("  Type: %s\n", desc.Type)

		if len(desc.ContextAttributes) > 0 {
			fmt.Printf("  Context Attributes:\n")
			count := 0
			for key, value := range desc.ContextAttributes {
				if count < 5 {
					fmt.Printf("    %s: %v\n", key, value)
					count++
				}
			}
			if len(desc.ContextAttributes) > 5 {
				fmt.Printf("    ... and %d more attributes\n", len(desc.ContextAttributes)-5)
			}
		}

		fmt.Println()

		if i >= 9 { // Show first 10 descriptors
			remaining := len(descriptors.Data) - 10
			if remaining > 0 {
				fmt.Printf("... and %d more descriptors\n", remaining)
			}
			break
		}
	}

	fmt.Printf("\nNote: Object descriptors are lightweight references without full object attributes.\n")
	fmt.Printf("Use GetObjectsRelatedToFileBehaviour for complete object data.\n")

	logger.Info("Object descriptors retrieved successfully",
		zap.String("sandbox_id", sandboxID),
		zap.String("relationship", relationship),
		zap.Int("descriptor_count", len(descriptors.Data)))
}
