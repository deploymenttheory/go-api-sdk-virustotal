# Timeouts & Retries

## What are Timeouts and Retries?

Timeouts control how long the SDK waits for an API response before giving up. Retries automatically retry failed requests when they encounter transient errors like network issues or rate limits.

## Why Use Timeouts and Retries?

Proper timeout and retry configuration helps you:

- **Prevent hanging requests** - Avoid waiting indefinitely for responses
- **Handle transient failures** - Automatically recover from temporary network issues
- **Respect rate limits** - Retry with backoff when hitting API quotas
- **Improve reliability** - Make your application more resilient to intermittent failures
- **Control resource usage** - Free up resources from slow or failing requests

## When to Use It

Configure timeouts and retries when:

- Making API calls over unreliable networks
- Running long-lived services that need resilience
- Implementing critical workflows that must handle transient failures
- Dealing with rate-limited APIs
- Running in production environments where reliability is critical

## Basic Example

Here's how to configure timeouts and retries:

```go
package main

import (
    "context"
    "log"
    "os"
    "time"

    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
)

func main() {
    // Create client with timeout and retry configuration
    vtClient, err := client.NewClient(
        os.Getenv("VT_API_KEY"),
        client.WithTimeout(30*time.Second),  // 30 second timeout
        client.WithRetryCount(3),             // Retry up to 3 times
    )
    if err != nil {
        log.Fatal(err)
    }

    // Use the client - timeouts and retries are automatic
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

**What happens:**
- If the request takes longer than 30 seconds, it times out
- If the request fails with a retryable error, it automatically retries up to 3 times
- Retries use exponential backoff to avoid overwhelming the server

## Alternative Configuration Options

### Option 1: Custom Timeout

Set a timeout appropriate for your use case:

```go
// Short timeout for quick operations
vtClient, err := client.NewClient(
    apiKey,
    client.WithTimeout(10*time.Second),
)

// Longer timeout for large file downloads
vtClient, err := client.NewClient(
    apiKey,
    client.WithTimeout(5*time.Minute),
)
```

**When to use:**
- Short timeouts (5-15s): Simple lookups, file reports
- Medium timeouts (30-60s): File uploads, URL scans
- Long timeouts (2-5min): Large file downloads, bulk operations

**Default:** 120 seconds (2 minutes)

---

### Option 2: Retry Configuration

Configure retry behavior for different scenarios:

```go
import "time"

// Conservative: Few retries, quick backoff
vtClient, err := client.NewClient(
    apiKey,
    client.WithRetryCount(2),                      // Retry twice
    client.WithRetryWaitTime(2*time.Second),       // Wait 2s between retries
    client.WithRetryMaxWaitTime(10*time.Second),   // Max wait 10s
)

// Aggressive: More retries, longer backoff
vtClient, err := client.NewClient(
    apiKey,
    client.WithRetryCount(5),                      // Retry 5 times
    client.WithRetryWaitTime(5*time.Second),       // Wait 5s between retries
    client.WithRetryMaxWaitTime(60*time.Second),   // Max wait 60s
)
```

**When to use:**
- Conservative: Rate-limited APIs, quick failures preferred
- Aggressive: Unreliable networks, high importance operations

**Defaults:**
- Retry count: 3
- Wait time: 2 seconds
- Max wait time: 10 seconds

---

### Option 3: Context-Based Timeouts

Use context for per-request timeouts:

```go
func getFileReportWithTimeout(filesService *files.Service, hash string) error {
    // Create context with 5 second timeout for this specific request
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    result, _, err := filesService.GetFileReport(ctx, hash)
    if err != nil {
        if ctx.Err() == context.DeadlineExceeded {
            return fmt.Errorf("request timed out after 5 seconds")
        }
        return err
    }

    log.Printf("File: %s", result.Data.Attributes.MeaningfulName)
    return nil
}
```

**When to use:** When different operations need different timeouts, or when you want dynamic timeout control.

**Note:** Context timeout takes precedence over client timeout.

---

### Option 4: Disable Retries

Disable retries when you want to fail fast:

```go
// No retries - fail immediately on any error
vtClient, err := client.NewClient(
    apiKey,
    client.WithRetryCount(0),
)
```

**When to use:**
- Testing/debugging
- Operations where retries don't make sense (non-idempotent operations)
- When you want to implement custom retry logic

---

## Retry Behavior

### What Gets Retried

The SDK automatically retries:
- ✅ Network errors (connection refused, timeout, etc.)
- ✅ 5xx server errors (500, 502, 503, 504)
- ✅ 429 rate limit errors
- ✅ Request timeout errors

### What Doesn't Get Retried

The SDK does NOT retry:
- ❌ 4xx client errors (400, 401, 403, 404) - these won't succeed on retry
- ❌ Successful responses (2xx)
- ❌ Context cancellation
- ❌ Invalid request configuration

### Exponential Backoff

Retries use exponential backoff with jitter:

```
Retry 1: Wait 2s  (base wait time)
Retry 2: Wait 4s  (2x)
Retry 3: Wait 8s  (4x, capped at max wait time)
```

This prevents overwhelming the server and respects rate limits.

## Common Patterns

### Pattern 1: Production-Ready Configuration

```go
vtClient, err := client.NewClient(
    apiKey,
    client.WithTimeout(30*time.Second),
    client.WithRetryCount(3),
    client.WithRetryWaitTime(2*time.Second),
    client.WithRetryMaxWaitTime(10*time.Second),
)
```

### Pattern 2: High-Availability Configuration

```go
// More aggressive retries for critical operations
vtClient, err := client.NewClient(
    apiKey,
    client.WithTimeout(60*time.Second),
    client.WithRetryCount(5),
    client.WithRetryWaitTime(10*time.Second),
    client.WithRetryMaxWaitTime(2*time.Minute),
)
```

### Pattern 3: Fast-Fail Configuration

```go
// Fail quickly for non-critical operations
vtClient, err := client.NewClient(
    apiKey,
    client.WithTimeout(10*time.Second),
    client.WithRetryCount(1),
    client.WithRetryWaitTime(1*time.Second),
)
```

## Handling Timeout Errors

```go
import "context"

result, _, err := filesService.GetFileReport(ctx, hash)
if err != nil {
    // Check if error is due to timeout
    if ctx.Err() == context.DeadlineExceeded {
        log.Println("Request timed out - consider increasing timeout")
        return
    }

    // Check if error is transient (should retry)
    if client.IsServerError(err) || client.IsRateLimited(err) {
        log.Println("Transient error - retries were exhausted")
        return
    }

    // Other error
    log.Printf("Request failed: %v", err)
}
```

## Troubleshooting

### Request Always Times Out

**Symptoms:** Consistent timeout errors even with retries

**Solutions:**
1. Increase timeout: `client.WithTimeout(5*time.Minute)`
2. Check network connectivity
3. Verify VirusTotal API is accessible
4. Check for proxy/firewall issues

### Too Many Retries

**Symptoms:** Requests taking very long to fail

**Solutions:**
1. Reduce retry count: `client.WithRetryCount(1)`
2. Decrease wait time: `client.WithRetryWaitTime(2*time.Second)`
3. Check if the error is retryable (4xx errors shouldn't be retried)

### Rate Limit Errors Persist

**Symptoms:** Still getting 429 errors after retries

**Solutions:**
1. Increase max wait time: `client.WithRetryMaxWaitTime(60*time.Second)`
2. Implement application-level rate limiting
3. Consider upgrading to a higher-tier API key

See [Rate Limiting Guide](rate-limiting.md) for more details.

## Testing

### Simulating Timeouts

```go
func TestTimeout(t *testing.T) {
    // Create client with very short timeout
    vtClient, _ := client.NewClient(
        "test-api-key",
        client.WithTimeout(1*time.Millisecond),
    )

    // This will timeout
    ctx := context.Background()
    _, _, err := filesService.GetFileReport(ctx, "hash")

    assert.Error(t, err)
}
```

### Testing Retry Logic

```go
func TestRetries(t *testing.T) {
    // Create client with retries disabled for predictable testing
    vtClient, _ := client.NewClient(
        "test-api-key",
        client.WithRetryCount(0),
    )

    // Test that errors are returned immediately
    // ... your test code
}
```

## Related Documentation

- [Error Handling](error-handling.md) - Handle timeout and retry errors
- [Rate Limiting](rate-limiting.md) - Understand API quotas and 429 errors
- [Context Support](context.md) - Use context for request control
- [Authentication](authentication.md) - Configure API access
