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

	summary, _, err := vtClient.FileBehaviours.GetFileBehaviourSummaryByHashId(ctx, fileID)
	if err != nil {
		log.Fatalf("Failed to get file behaviour summary: %v", err)
	}

	fmt.Printf("\n=== File Behaviour Summary ===\n")
	fmt.Printf("File ID: %s\n\n", fileID)

	data := summary.Data

	if len(data.ProcessesTree) > 0 {
		fmt.Printf("Process Tree:\n")
		for i, proc := range data.ProcessesTree {
			if i < 5 { // Show first 5 processes
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
		fmt.Printf("Files Opened: %d files\n", len(data.FilesOpened))
		for i, file := range data.FilesOpened {
			if i < 3 {
				fmt.Printf("  - %s\n", file)
			}
		}
		if len(data.FilesOpened) > 3 {
			fmt.Printf("  ... and %d more files\n", len(data.FilesOpened)-3)
		}
		fmt.Println()
	}

	if len(data.ModulesLoaded) > 0 {
		fmt.Printf("Modules Loaded: %d modules\n", len(data.ModulesLoaded))
		for i, module := range data.ModulesLoaded {
			if i < 3 {
				fmt.Printf("  - %s\n", module)
			}
		}
		if len(data.ModulesLoaded) > 3 {
			fmt.Printf("  ... and %d more modules\n", len(data.ModulesLoaded)-3)
		}
		fmt.Println()
	}

	if len(data.RegistryKeysOpened) > 0 {
		fmt.Printf("Registry Keys Opened: %d keys\n", len(data.RegistryKeysOpened))
		for i, key := range data.RegistryKeysOpened {
			if i < 3 {
				fmt.Printf("  - %s\n", key)
			}
		}
		if len(data.RegistryKeysOpened) > 3 {
			fmt.Printf("  ... and %d more keys\n", len(data.RegistryKeysOpened)-3)
		}
		fmt.Println()
	}

	if len(data.MutexesCreated) > 0 {
		fmt.Printf("Mutexes Created: %d\n", len(data.MutexesCreated))
	}

	if len(data.Tags) > 0 {
		fmt.Printf("Tags: %v\n", data.Tags)
	}

	logger.Info("File behaviour summary retrieved successfully",
		zap.String("file_id", fileID),
		zap.Int("processes", len(data.ProcessesTree)),
		zap.Int("files_opened", len(data.FilesOpened)))
}
