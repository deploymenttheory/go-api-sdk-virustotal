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

	htmlReport, _, err := vtClient.FileBehaviours.GetFileBehaviourHTML(ctx, sandboxID)
	if err != nil {
		log.Fatalf("Failed to get HTML report: %v", err)
	}

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
