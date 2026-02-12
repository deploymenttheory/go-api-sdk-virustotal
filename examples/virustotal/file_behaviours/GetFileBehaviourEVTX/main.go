package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

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

	evtxData, _, err := vtClient.FileBehaviours.GetFileBehaviourEVTX(ctx, sandboxID)
	if err != nil {
		log.Fatalf("Failed to get EVTX file: %v", err)
	}

	fmt.Printf("\n=== File Behaviour EVTX ===\n")
	fmt.Printf("Sandbox ID: %s\n", sandboxID)
	fmt.Printf("EVTX File Size: %d bytes\n\n", len(evtxData))

	// Save to file
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, "behaviour_report.evtx")
	if err := os.WriteFile(outputFile, evtxData, 0644); err != nil {
		log.Fatalf("Failed to save EVTX file: %v", err)
	}

	fmt.Printf("EVTX file saved to: %s\n", outputFile)
	fmt.Printf("\nNote: EVTX files contain Windows Event Logs from the sandbox analysis.\n")
	fmt.Printf("Use Windows Event Viewer or specialized tools to analyze this file.\n")

	logger.Info("EVTX file retrieved successfully",
		zap.String("sandbox_id", sandboxID),
		zap.Int("file_size", len(evtxData)),
		zap.String("output_file", outputFile))
}
