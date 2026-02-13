package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/urls"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
)

// This example demonstrates creating a client with OpenTelemetry tracing for observability.
//
// Use this approach when:
// - You need distributed tracing across microservices
// - You want to monitor API performance and latency
// - You need to track errors and failures in production
// - You're using observability platforms (Jaeger, Zipkin, DataDog, etc.)
// - You want complete visibility into API call chains
//
// This example shows:
// - OpenTelemetry tracer provider setup
// - Client instrumentation with tracing
// - Automatic span creation for HTTP requests
// - Trace export to stdout (replace with your backend)
// - Combined logging and tracing for full observability

func main() {
	// Check API key from environment
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

	// Step 1: Create structured logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	// Step 2: Initialize OpenTelemetry exporter
	// In production, replace stdout exporter with:
	// - OTLP exporter for OpenTelemetry Collector
	// - Jaeger exporter for Jaeger
	// - Zipkin exporter for Zipkin
	// - DataDog, Honeycomb, New Relic, etc.
	exporter, err := stdouttrace.New(
		stdouttrace.WithPrettyPrint(),
	)
	if err != nil {
		log.Fatalf("Failed to create trace exporter: %v", err)
	}

	// Step 3: Create tracer provider
	tracerProvider := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		// Add resource attributes for better trace context
		// trace.WithResource(resource.NewWithAttributes(
		//     semconv.SchemaURL,
		//     semconv.ServiceName("virustotal-client"),
		//     semconv.ServiceVersion("1.0.0"),
		// )),
	)
	defer func() {
		if err := tracerProvider.Shutdown(context.Background()); err != nil {
			logger.Error("Failed to shutdown tracer provider", zap.Error(err))
		}
	}()

	// Set as global tracer provider
	otel.SetTracerProvider(tracerProvider)

	// Step 4: Create client with tracing enabled
	vtClient, err := client.NewClient(
		apiKey,
		// Enable structured logging
		client.WithLogger(logger),

		// Enable OpenTelemetry tracing - this automatically instruments all HTTP calls
		client.WithTracing(nil), // nil uses default config with global tracer provider

		// Or use custom tracing configuration:
		// client.WithTracing(&client.OTelConfig{
		//     TracerProvider: tracerProvider,
		//     ServiceName:    "my-virustotal-app",
		//     SpanNameFormatter: func(operation string, req *http.Request) string {
		//         return fmt.Sprintf("VT: %s %s", req.Method, req.URL.Path)
		//     },
		// }),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	logger.Info("VirusTotal client created with OpenTelemetry tracing")

	// Step 5: Use the client - tracing happens automatically!
	ctx := context.Background()
	urlsService := urls.NewService(vtClient)

	// This API call will automatically create spans with:
	// - HTTP method, URL, and status code
	// - Request/response timing
	// - Error details (if any)
	// - All OpenTelemetry semantic conventions
	urlToScan := "https://www.example.com"

	logger.Info("Scanning URL", zap.String("url", urlToScan))

	scanResult, resp, err := urlsService.ScanURL(ctx, urlToScan)
	if err != nil {
		logger.Error("URL scan failed",
			zap.String("url", urlToScan),
			zap.Error(err))
		log.Fatalf("API call failed: %v", err)
	}

	logger.Info("URL scan submitted",
		zap.String("url", urlToScan),
		zap.String("analysis_id", scanResult.Data.ID),
		zap.Int("status_code", resp.StatusCode),
		zap.Duration("duration", resp.Duration))

	// Display results
	fmt.Printf("\n✓ Client created with OpenTelemetry tracing\n\n")
	fmt.Printf("Observability Setup:\n")
	fmt.Printf("  Tracing: Enabled (OpenTelemetry)\n")
	fmt.Printf("  Exporter: stdout (replace with your backend)\n")
	fmt.Printf("  Logging: zap (structured)\n")
	fmt.Printf("  Service: virustotal-client\n")

	fmt.Printf("\nURL Scan Result:\n")
	fmt.Printf("  URL: %s\n", urlToScan)
	fmt.Printf("  Analysis ID: %s\n", scanResult.Data.ID)
	fmt.Printf("  Status Code: %d\n", resp.StatusCode)
	fmt.Printf("  Duration: %v\n", resp.Duration)
	fmt.Printf("  Self Link: %s\n", scanResult.Data.Links.Self)

	fmt.Printf("\n📊 Trace Information:\n")
	fmt.Printf("Check the output above for detailed trace spans.\n")
	fmt.Printf("Each HTTP request is automatically instrumented with:\n")
	fmt.Printf("  - HTTP method and URL\n")
	fmt.Printf("  - Request/response timing\n")
	fmt.Printf("  - Status codes and errors\n")
	fmt.Printf("  - OpenTelemetry semantic conventions\n")

	fmt.Printf("\n✓ OpenTelemetry client example completed successfully!\n")
	fmt.Printf("\nNext Steps:\n")
	fmt.Printf("  1. Replace stdout exporter with your observability backend\n")
	fmt.Printf("  2. Add resource attributes for better trace context\n")
	fmt.Printf("  3. Configure sampling for production workloads\n")
	fmt.Printf("  4. View traces in your observability platform\n")
}
