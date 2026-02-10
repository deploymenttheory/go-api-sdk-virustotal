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
	// Sandbox ID format: {file_sha256}_{sandbox_name}
	sandboxID := "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f_VirusTotal Jujubox"

	htmlReport, err := vtClient.FileBehaviours.GetFileBehaviourHTML(ctx, sandboxID)
	if err != nil {
		log.Fatalf("Failed to get HTML report: %v", err)
	}

	// Print results
	fmt.Printf("\n=== File Behaviour HTML Report ===\n")
	fmt.Printf("Sandbox ID: %s\n", sandboxID)
	fmt.Printf("HTML Report Size: %d bytes\n\n", len(htmlReport))

	// Save to file
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, "behaviour_report.html")
	if err := os.WriteFile(outputFile, []byte(htmlReport), 0644); err != nil {
		log.Fatalf("Failed to save HTML report: %v", err)
	}

	fmt.Printf("HTML report saved to: %s\n", outputFile)
	fmt.Printf("Open this file in a web browser to view the detailed behaviour report\n")

	// Show preview of HTML content
	preview := htmlReport
	if len(htmlReport) > 500 {
		preview = htmlReport[:500]
	}
	fmt.Printf("\nHTML Preview (first 500 chars):\n%s\n...\n", preview)

	logger.Info("HTML report retrieved successfully",
		zap.String("sandbox_id", sandboxID),
		zap.Int("html_size", len(htmlReport)),
		zap.String("output_file", outputFile))
}
