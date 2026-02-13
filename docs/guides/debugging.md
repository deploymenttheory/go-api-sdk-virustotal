# Debug Mode

## What is Debug Mode?

Debug mode enables detailed logging of all HTTP requests and responses, including headers, bodies, and timing information. This helps troubleshoot issues and understand exactly what the SDK is sending to the VirusTotal API.

## Why Use Debug Mode?

Debug mode helps you:

- **Troubleshoot issues** - See exactly what's being sent and received
- **Verify requests** - Confirm API calls are formatted correctly
- **Inspect responses** - View raw API responses for debugging
- **Monitor traffic** - Understand request/response patterns
- **Learn the API** - See how the SDK interacts with VirusTotal

## When to Enable It

Enable debug mode when:

- Debugging integration issues
- Investigating unexpected API responses
- Troubleshooting authentication problems
- Verifying request formats
- Learning how the SDK works
- **Only in development** - Never enable in production!

## Basic Example

Here's how to enable debug mode:

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
)

func main() {
    // Enable debug mode
    vtClient, err := client.NewClient(
        os.Getenv("VT_API_KEY"),
        client.WithDebug(),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Make a request - detailed output will be printed
    filesService := files.NewService(vtClient)
    result, _, err := filesService.GetFileReport(
        context.Background(),
        "44d88612fea8a8f36de82e1278abb02f",
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("File: %s", result.Data.Attributes.MeaningfulName)
}
```

**Debug Output:**
```
2024-01-15 10:30:45 | GET | https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f
REQUEST HEADERS:
  Accept-Encoding: gzip
  User-Agent: go-api-sdk-virustotal/1.0.0; gzip
  X-Apikey: ***redacted***

RESPONSE:
  Status Code: 200
  Proto: HTTP/2.0
  Duration: 245ms
RESPONSE HEADERS:
  Content-Type: application/json
  X-Ratelimit-Hourly-Limit: 4
  X-Ratelimit-Hourly-Remaining: 3

RESPONSE BODY:
{
  "data": {
    "id": "44d88612fea8a8f36de82e1278abb02f",
    "type": "file",
    "attributes": {
      "meaningful_name": "eicar.com",
      ...
    }
  }
}
```

## Configuration Options

### Option 1: Basic Debug Mode

Enable standard debug output:

```go
vtClient, err := client.NewClient(
    apiKey,
    client.WithDebug(),
)
```

**When to use:** General debugging and troubleshooting

**Output includes:**
- Request method and URL
- Request headers (API key redacted)
- Response status and headers
- Response body
- Request duration

---

### Option 2: Debug Mode with Custom Logger

Combine debug mode with structured logging:

```go
import "go.uber.org/zap"

logger, _ := zap.NewDevelopment()

vtClient, err := client.NewClient(
    apiKey,
    client.WithLogger(logger),
    client.WithDebug(),
)
```

**When to use:** Structured debug output for parsing or analysis

---

### Option 3: Conditional Debug Mode

Enable debug mode based on environment:

```go
var options []client.ClientOption

if os.Getenv("DEBUG") == "true" {
    options = append(options, client.WithDebug())
}

vtClient, err := client.NewClient(apiKey, options...)
```

**When to use:** Toggle debug mode without code changes

```bash
# Enable debug mode
DEBUG=true go run main.go

# Disable debug mode
go run main.go
```

---

### Option 4: Debug Mode with Body Limit

Limit the size of bodies logged (useful for large responses):

```go
vtClient, err := client.NewClient(
    apiKey,
    client.WithDebug(),
    // Note: Body limit configuration would be in WithDebug options
    // This example shows the pattern
)
```

**When to use:** Debugging endpoints that return large payloads

---

## What Gets Logged

### Request Information
```
GET https://www.virustotal.com/api/v3/files/{hash}
REQUEST HEADERS:
  User-Agent: go-api-sdk-virustotal/1.0.0
  X-Apikey: ***redacted***
  Custom-Header: value
```

### Response Information
```
RESPONSE:
  Status Code: 200 OK
  Proto: HTTP/2.0
  Duration: 234ms

RESPONSE HEADERS:
  Content-Type: application/json
  X-Ratelimit-Hourly-Limit: 4
  X-Ratelimit-Hourly-Remaining: 3

RESPONSE BODY:
{ ... full JSON response ... }
```

### Error Responses
```
RESPONSE:
  Status Code: 404 Not Found
  Duration: 123ms

RESPONSE BODY:
{
  "error": {
    "code": "NotFoundError",
    "message": "File not found"
  }
}
```

## Common Debugging Scenarios

### Scenario 1: Authentication Issues

```go
// Enable debug to see authentication headers
vtClient, _ := client.NewClient(
    apiKey,
    client.WithDebug(),
)

// Check if API key is being sent correctly
_, _, err := filesService.GetFileReport(ctx, hash)
// Look for "X-Apikey" header in debug output
```

### Scenario 2: Rate Limiting

```go
vtClient, _ := client.NewClient(
    apiKey,
    client.WithDebug(),
)

// Debug output shows rate limit headers
_, _, err := filesService.GetFileReport(ctx, hash)
// Look for X-Ratelimit-* headers in response
```

### Scenario 3: Request Format Verification

```go
// Verify POST request body format
vtClient, _ := client.NewClient(
    apiKey,
    client.WithDebug(),
)

// Debug shows actual JSON being sent
_, _, err := filesService.UploadFile(ctx, uploadRequest)
```

### Scenario 4: Proxy Issues

```go
// Debug proxy connections
vtClient, _ := client.NewClient(
    apiKey,
    client.WithProxy("http://proxy:8080"),
    client.WithDebug(),
)

// See if requests are going through proxy
_, _, err := filesService.GetFileReport(ctx, hash)
```

### Scenario 5: TLS Certificate Issues

```go
// Debug TLS handshake
vtClient, _ := client.NewClient(
    apiKey,
    client.WithRootCertificates("/path/to/ca.pem"),
    client.WithDebug(),
)

// See TLS-related errors in debug output
_, _, err := filesService.GetFileReport(ctx, hash)
```

## Security Warnings

⚠️ **NEVER enable debug mode in production!**

Debug mode logs sensitive information:
- **API keys** (partially redacted but still visible in logs)
- **Request/response bodies** (may contain sensitive data)
- **Headers** (may contain tokens or credentials)
- **URLs** (may contain parameters)

### Safe Debug Practices

✅ **Do:**
- Use only in development/testing
- Clear debug logs before committing
- Use environment variables to toggle debug
- Redact sensitive data from debug logs
- Limit debug output to necessary information

❌ **Don't:**
- Enable in production
- Commit debug output to version control
- Share debug logs containing secrets
- Log to public systems with debug enabled
- Leave debug mode on continuously

## Disabling Debug Mode

```go
// Simply omit WithDebug() option
vtClient, err := client.NewClient(apiKey)

// Or conditionally disable
var options []client.ClientOption
if os.Getenv("ENVIRONMENT") != "production" {
    options = append(options, client.WithDebug())
}
vtClient, err := client.NewClient(apiKey, options...)
```

## Alternative Debugging Tools

### HTTP Proxies

Use HTTP debugging proxies for advanced inspection:

```bash
# Charles Proxy, mitmproxy, Burp Suite, etc.
mitmproxy -p 8080
```

```go
vtClient, _ := client.NewClient(
    apiKey,
    client.WithProxy("http://127.0.0.1:8080"),
    client.WithInsecureSkipVerify(), // For proxy SSL inspection
)
```

### Network Monitoring

Use system tools to monitor HTTP traffic:

```bash
# tcpdump
sudo tcpdump -i any -A 'host www.virustotal.com'

# Wireshark
# Use GUI to filter: http.host == "www.virustotal.com"
```

### Structured Logging

Use structured logging instead of debug mode for production:

```go
import "go.uber.org/zap"

logger, _ := zap.NewProduction()
vtClient, _ := client.NewClient(
    apiKey,
    client.WithLogger(logger),
)

// Log specific operations
logger.Info("Making API call",
    zap.String("endpoint", "/files/"+hash),
    zap.String("method", "GET"),
)
```

## Testing with Debug Mode

```go
func TestWithDebug(t *testing.T) {
    // Enable debug for specific test
    vtClient, err := client.NewClient(
        "test-key",
        client.WithDebug(),
    )
    require.NoError(t, err)

    // Debug output helps verify test behavior
    // ...
}
```

### Capturing Debug Output

```go
import (
    "bytes"
    "log"
)

func TestDebugOutput(t *testing.T) {
    // Capture debug output
    var buf bytes.Buffer
    log.SetOutput(&buf)
    defer log.SetOutput(os.Stderr)

    vtClient, _ := client.NewClient(
        "test-key",
        client.WithDebug(),
    )

    // Make request...

    // Verify debug output
    output := buf.String()
    assert.Contains(t, output, "REQUEST HEADERS")
    assert.Contains(t, output, "RESPONSE")
}
```

## Related Documentation

- [Logging](logging.md) - Structured logging for production
- [OpenTelemetry](opentelemetry.md) - Distributed tracing for observability
- [Authentication](authentication.md) - Debug authentication issues
- [Proxy Support](proxy.md) - Debug proxy connections
- [TLS Configuration](tls-configuration.md) - Debug TLS issues
