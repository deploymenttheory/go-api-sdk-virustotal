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
	fileID := "44d88612fea8a8f36de82e1278abb02f" // Example MD5 hash (EICAR test file)

	mitreData, _, err := vtClient.FileBehaviours.GetFileMitreAttackTrees(ctx, fileID)
	if err != nil {
		log.Fatalf("Failed to get MITRE ATT&CK trees: %v", err)
	}

	fmt.Printf("\n=== MITRE ATT&CK Techniques ===\n")
	fmt.Printf("File ID: %s\n\n", fileID)

	if len(mitreData.Data) == 0 {
		fmt.Println("No MITRE ATT&CK techniques observed")
		return
	}

	// Iterate through each sandbox's MITRE data
	for sandboxName, sandboxTactics := range mitreData.Data {
		fmt.Printf("Sandbox: %s\n", sandboxName)

		if len(sandboxTactics.Tactics) == 0 {
			fmt.Println("  No tactics observed")
			continue
		}

		for _, tactic := range sandboxTactics.Tactics {
			fmt.Printf("  Tactic: %s - %s\n", tactic.ID, tactic.Name)

			if len(tactic.Techniques) > 0 {
				fmt.Printf("    Techniques:\n")
				for _, technique := range tactic.Techniques {
					fmt.Printf("      - %s: %s\n", technique.ID, technique.Name)

					if len(technique.Signatures) > 0 {
						fmt.Printf("        Signatures:\n")
						for _, sig := range technique.Signatures {
							fmt.Printf("          - %s: %s\n", sig.Severity, sig.Description)
						}
					}
				}
			}
		}
		fmt.Println()
	}

	logger.Info("MITRE ATT&CK trees retrieved successfully",
		zap.String("file_id", fileID),
		zap.Int("sandbox_count", len(mitreData.Data)))
}
