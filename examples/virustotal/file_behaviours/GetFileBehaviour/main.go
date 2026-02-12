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
	// Example: replace with an actual sandbox ID from your GetAllFileBehaviours results
	sandboxID := "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f_VirusTotal Jujubox"

	behaviour, _, err := vtClient.FileBehaviours.GetFileBehaviour(ctx, sandboxID)
	if err != nil {
		log.Fatalf("Failed to get file behaviour: %v", err)
	}

	fmt.Printf("\n=== File Behaviour Report ===\n")
	fmt.Printf("Sandbox ID: %s\n", behaviour.Data.ID)
	fmt.Printf("Type: %s\n\n", behaviour.Data.Type)

	attrs := behaviour.Data.Attributes

	fmt.Printf("Sandbox Information:\n")
	if attrs.SandboxName != "" {
		fmt.Printf("  Sandbox: %s\n", attrs.SandboxName)
	}
	if attrs.AnalysisDate > 0 {
		fmt.Printf("  Analysis Date: %s\n", time.Unix(attrs.AnalysisDate, 0))
	}
	fmt.Println()

	if len(attrs.ProcessesTree) > 0 {
		fmt.Printf("Process Tree: %d processes\n", len(attrs.ProcessesTree))
		for i, proc := range attrs.ProcessesTree {
			if i < 3 {
				fmt.Printf("  - %s\n", proc.Name)
				if proc.ProcessID != "" {
					fmt.Printf("    PID: %s\n", proc.ProcessID)
				}
			}
		}
		if len(attrs.ProcessesTree) > 3 {
			fmt.Printf("  ... and %d more processes\n", len(attrs.ProcessesTree)-3)
		}
		fmt.Println()
	}

	if len(attrs.FilesOpened) > 0 {
		fmt.Printf("Files Opened: %d\n", len(attrs.FilesOpened))
	}

	if len(attrs.ModulesLoaded) > 0 {
		fmt.Printf("Modules Loaded: %d\n", len(attrs.ModulesLoaded))
	}

	if len(attrs.RegistryKeysOpened) > 0 {
		fmt.Printf("Registry Keys Opened: %d\n", len(attrs.RegistryKeysOpened))
	}

	if len(attrs.IPTraffic) > 0 {
		fmt.Printf("\nNetwork Activity:\n")
		fmt.Printf("  IP Traffic Entries: %d\n", len(attrs.IPTraffic))
	}

	if len(attrs.DNSLookups) > 0 {
		fmt.Printf("  DNS Lookups:\n")
		for i, lookup := range attrs.DNSLookups {
			if i < 5 {
				fmt.Printf("    - Hostname: %s\n", lookup.Hostname)
			}
		}
		if len(attrs.DNSLookups) > 5 {
			fmt.Printf("    ... and %d more lookups\n", len(attrs.DNSLookups)-5)
		}
	}

	if len(attrs.Tags) > 0 {
		fmt.Printf("\nTags: %v\n", attrs.Tags)
	}

	logger.Info("File behaviour report retrieved successfully",
		zap.String("sandbox_id", sandboxID),
		zap.String("sandbox_name", attrs.SandboxName))
}
