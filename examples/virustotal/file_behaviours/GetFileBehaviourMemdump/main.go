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

	memdumpData, err := vtClient.FileBehaviours.GetFileBehaviourMemdump(ctx, sandboxID)
	if err != nil {
		log.Fatalf("Failed to get memory dump: %v", err)
	}

	fmt.Printf("\n=== File Behaviour Memory Dump ===\n")
	fmt.Printf("Sandbox ID: %s\n", sandboxID)
	fmt.Printf("Memory Dump Size: %d bytes (%.2f MB)\n\n", len(memdumpData), float64(len(memdumpData))/1024/1024)

	// Save to file
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, "behaviour_report.memdump")
	if err := os.WriteFile(outputFile, memdumpData, 0644); err != nil {
		log.Fatalf("Failed to save memory dump: %v", err)
	}

	fmt.Printf("Memory dump saved to: %s\n", outputFile)
	fmt.Printf("\nNote: Memory dumps contain process memory captured during sandbox analysis.\n")
	fmt.Printf("Use memory forensics tools (e.g., Volatility) to analyze this file.\n")
	fmt.Printf("Warning: Memory dumps can be very large files.\n")

	logger.Info("Memory dump retrieved successfully",
		zap.String("sandbox_id", sandboxID),
		zap.Int("file_size", len(memdumpData)),
		zap.String("output_file", outputFile))
}
