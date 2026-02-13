package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
)

// This example demonstrates how to enable OpenTelemetry tracing for VirusTotal API calls.
//
// OpenTelemetry tracing provides:
// - Distributed tracing across API calls
// - Performance monitoring
// - Error tracking
// - Integration with observability platforms (Jaeger, Zipkin, DataDog, etc.)
//
// The SDK uses the clean middleware pattern from otelhttp, so all HTTP calls
// are automatically instrumented without code changes in your business logic.

func main() {
	// Get API key from environment variable
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

	// Step 1: Initialize OpenTelemetry exporter
	// This example uses stdout exporter for demonstration.
	// In production, use exporters like OTLP, Jaeger, Zipkin, etc.
	exporter, err := stdouttrace.New(
		stdouttrace.WithPrettyPrint(),
	)
	if err != nil {
		log.Fatalf("Failed to create stdout exporter: %v", err)
	}

	// Step 2: Create a tracer provider
	tracerProvider := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
	)
	defer func() {
		if err := tracerProvider.Shutdown(context.Background()); err != nil {
			log.Printf("Error shutting down tracer provider: %v", err)
		}
	}()

	// Set as global tracer provider (optional, but recommended)
	otel.SetTracerProvider(tracerProvider)

	// Step 3: Create VirusTotal client with tracing enabled
	// Option 1: Use default tracing config (uses global tracer provider)
	vtClient, err := client.NewClient(
		apiKey,
		client.WithTracing(nil), // nil uses default config
	)
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Option 2: Use custom tracing configuration
	// Uncomment to use custom config:
	/*
		otelConfig := &client.OTelConfig{
			TracerProvider: tracerProvider,
			ServiceName:    "my-virustotal-app",
			SpanNameFormatter: func(operation string, req *http.Request) string {
				// Custom span naming: "VirusTotal: GET /files/{hash}"
				return fmt.Sprintf("VirusTotal: %s %s", req.Method, req.URL.Path)
			},
		}
		vtClient, err := client.NewClient(
			apiKey,
			client.WithTracing(otelConfig),
		)
	*/

	// Step 4: Use the client normally - tracing happens automatically!
	ctx := context.Background()
	filesService := files.NewService(vtClient)

	// This API call will automatically create spans for:
	// - The HTTP request/response
	// - Timing information
	// - Status codes and errors
	fileHash := "44d88612fea8a8f36de82e1278abb02f" // EICAR test file
	fileReport, resp, err := filesService.GetFileReport(ctx, fileHash)

	if err != nil {
		log.Printf("Error getting file report: %v", err)
		return
	}

	fmt.Printf("File Report Retrieved (Status: %d)\n", resp.StatusCode)
	fmt.Printf("File Hash: %s\n", fileReport.Data.ID)
	fmt.Printf("Last Analysis Stats:\n")
	fmt.Printf("  Malicious: %d\n", fileReport.Data.Attributes.LastAnalysisStats.Malicious)
	fmt.Printf("  Suspicious: %d\n", fileReport.Data.Attributes.LastAnalysisStats.Suspicious)
	fmt.Printf("  Harmless: %d\n", fileReport.Data.Attributes.LastAnalysisStats.Harmless)

	// The trace will be exported to stdout (check the output below)
	// In production, traces would go to your observability platform
}

/*
Example trace output (stdout exporter):

{
	"Name": "HTTP GET",
	"SpanContext": {
		"TraceID": "f1d2d2f924e986ac86fdf7b36c94bcdf",
		"SpanID": "53995c3f42cd8ad7",
		"TraceFlags": "01",
		"TraceState": "",
		"Remote": false
	},
	"Parent": {...},
	"SpanKind": 3,
	"StartTime": "2024-01-15T10:30:45.123456789Z",
	"EndTime": "2024-01-15T10:30:45.456789123Z",
	"Attributes": [
		{
			"Key": "http.method",
			"Value": {"Type":"STRING","Value":"GET"}
		},
		{
			"Key": "http.url",
			"Value": {"Type":"STRING","Value":"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f"}
		},
		{
			"Key": "http.status_code",
			"Value": {"Type":"INT64","Value":200}
		},
		{
			"Key": "http.request_content_length",
			"Value": {"Type":"INT64","Value":0}
		},
		{
			"Key": "http.response_content_length",
			"Value": {"Type":"INT64","Value":2345}
		}
	],
	"Events": null,
	"Status": {
		"Code": "Ok",
		"Description": ""
	}
}

Benefits of this approach:
1. Zero boilerplate in business logic - just use the client normally
2. Automatic instrumentation of all HTTP calls
3. Follows OpenTelemetry semantic conventions
4. Works with any OpenTelemetry-compatible backend
5. Easy to enable/disable with a single option
*/
