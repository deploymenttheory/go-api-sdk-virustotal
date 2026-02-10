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
	fileHashes := []string{
		"44d88612fea8a8f36de82e1278abb02f", // EICAR test file MD5
		"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", // EICAR test file SHA-256
	}

	summary, err := vtClient.FileBehaviours.GetAllFileBehavioursSummary(ctx, fileHashes)
	if err != nil {
		log.Fatalf("Failed to get file behaviours summary: %v", err)
	}

	// Print results
	fmt.Printf("\n=== Multiple Files Behaviour Summary ===\n")
	fmt.Printf("Requested Files: %d\n\n", len(fileHashes))

	data := summary.Data

	if len(data.ProcessesTree) > 0 {
		fmt.Printf("Aggregated Process Tree: %d processes\n", len(data.ProcessesTree))
		for i, proc := range data.ProcessesTree {
			if i < 5 {
				fmt.Printf("  - Name: %s\n", proc.Name)
				if proc.ProcessID != "" {
					fmt.Printf("    PID: %s\n", proc.ProcessID)
				}
			}
		}
		if len(data.ProcessesTree) > 5 {
			fmt.Printf("  ... and %d more processes\n", len(data.ProcessesTree)-5)
		}
		fmt.Println()
	}

	if len(data.FilesOpened) > 0 {
		fmt.Printf("Total Files Opened: %d\n", len(data.FilesOpened))
	}

	if len(data.ModulesLoaded) > 0 {
		fmt.Printf("Total Modules Loaded: %d\n", len(data.ModulesLoaded))
	}

	if len(data.RegistryKeysOpened) > 0 {
		fmt.Printf("Total Registry Keys Opened: %d\n", len(data.RegistryKeysOpened))
	}

	if len(data.Tags) > 0 {
		fmt.Printf("\nAggregated Tags: %v\n", data.Tags)
	}

	logger.Info("Multiple files behaviour summary retrieved successfully",
		zap.Int("file_count", len(fileHashes)),
		zap.Int("total_processes", len(data.ProcessesTree)))
}
