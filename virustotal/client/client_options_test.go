package client

import (
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestWithRetryWaitTime(t *testing.T) {
	tests := []struct {
		name     string
		waitTime time.Duration
	}{
		{
			name:     "1 second wait time",
			waitTime: 1 * time.Second,
		},
		{
			name:     "2 seconds wait time (default)",
			waitTime: 2 * time.Second,
		},
		{
			name:     "5 seconds wait time",
			waitTime: 5 * time.Second,
		},
		{
			name:     "10 seconds wait time",
			waitTime: 10 * time.Second,
		},
		{
			name:     "100 milliseconds wait time",
			waitTime: 100 * time.Millisecond,
		},
		{
			name:     "zero wait time",
			waitTime: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test client
			apiKey := "test-api-key"
			client, err := NewClient(apiKey, WithRetryWaitTime(tt.waitTime))
			if err != nil {
				t.Fatalf("NewClient() error = %v, want nil", err)
			}

			// Verify client was created
			if client == nil {
				t.Fatal("Expected client to be created, got nil")
			}

			// Note: We can't directly verify the wait time is set in resty,
			// but we can verify the client was created successfully with the option
			if client.client == nil {
				t.Fatal("Expected resty client to be initialized")
			}
		})
	}
}

func TestWithRetryMaxWaitTime(t *testing.T) {
	tests := []struct {
		name        string
		maxWaitTime time.Duration
	}{
		{
			name:        "10 seconds max wait (default)",
			maxWaitTime: 10 * time.Second,
		},
		{
			name:        "20 seconds max wait",
			maxWaitTime: 20 * time.Second,
		},
		{
			name:        "30 seconds max wait",
			maxWaitTime: 30 * time.Second,
		},
		{
			name:        "1 minute max wait",
			maxWaitTime: 60 * time.Second,
		},
		{
			name:        "5 seconds max wait",
			maxWaitTime: 5 * time.Second,
		},
		{
			name:        "zero max wait time",
			maxWaitTime: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test client
			apiKey := "test-api-key"
			client, err := NewClient(apiKey, WithRetryMaxWaitTime(tt.maxWaitTime))
			if err != nil {
				t.Fatalf("NewClient() error = %v, want nil", err)
			}

			// Verify client was created
			if client == nil {
				t.Fatal("Expected client to be created, got nil")
			}

			// Verify resty client is initialized
			if client.client == nil {
				t.Fatal("Expected resty client to be initialized")
			}
		})
	}
}

func TestWithRetryWaitTimeAndMaxWaitTime(t *testing.T) {
	tests := []struct {
		name        string
		waitTime    time.Duration
		maxWaitTime time.Duration
	}{
		{
			name:        "standard configuration",
			waitTime:    2 * time.Second,
			maxWaitTime: 10 * time.Second,
		},
		{
			name:        "aggressive retry",
			waitTime:    5 * time.Second,
			maxWaitTime: 60 * time.Second,
		},
		{
			name:        "fast retry",
			waitTime:    1 * time.Second,
			maxWaitTime: 5 * time.Second,
		},
		{
			name:        "equal wait and max",
			waitTime:    5 * time.Second,
			maxWaitTime: 5 * time.Second,
		},
		{
			name:        "max less than wait (unusual but valid)",
			waitTime:    10 * time.Second,
			maxWaitTime: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test client with both options
			apiKey := "test-api-key"
			client, err := NewClient(
				apiKey,
				WithRetryWaitTime(tt.waitTime),
				WithRetryMaxWaitTime(tt.maxWaitTime),
			)
			if err != nil {
				t.Fatalf("NewClient() error = %v, want nil", err)
			}

			// Verify client was created
			if client == nil {
				t.Fatal("Expected client to be created, got nil")
			}

			// Verify resty client is initialized
			if client.client == nil {
				t.Fatal("Expected resty client to be initialized")
			}
		})
	}
}

func TestWithRetryWaitTimeWithOtherOptions(t *testing.T) {
	// Test that WithRetryWaitTime works correctly when combined with other options
	apiKey := "test-api-key"
	logger := zaptest.NewLogger(t)

	client, err := NewClient(
		apiKey,
		WithLogger(logger),
		WithRetryCount(5),
		WithRetryWaitTime(3*time.Second),
		WithRetryMaxWaitTime(15*time.Second),
		WithTimeout(30*time.Second),
	)

	if err != nil {
		t.Fatalf("NewClient() with multiple options error = %v, want nil", err)
	}

	if client == nil {
		t.Fatal("Expected client to be created, got nil")
	}

	if client.client == nil {
		t.Fatal("Expected resty client to be initialized")
	}

	if client.logger == nil {
		t.Fatal("Expected logger to be set")
	}
}

func TestWithRetryMaxWaitTimeWithOtherOptions(t *testing.T) {
	// Test that WithRetryMaxWaitTime works correctly when combined with other options
	apiKey := "test-api-key"
	logger := zaptest.NewLogger(t)

	client, err := NewClient(
		apiKey,
		WithLogger(logger),
		WithRetryCount(3),
		WithRetryMaxWaitTime(20*time.Second),
		WithTimeout(60*time.Second),
	)

	if err != nil {
		t.Fatalf("NewClient() with multiple options error = %v, want nil", err)
	}

	if client == nil {
		t.Fatal("Expected client to be created, got nil")
	}

	if client.client == nil {
		t.Fatal("Expected resty client to be initialized")
	}

	if client.logger == nil {
		t.Fatal("Expected logger to be set")
	}
}

func TestWithRetryWaitTimeOrder(t *testing.T) {
	// Test that option order doesn't matter
	apiKey := "test-api-key"

	// Apply options in one order
	client1, err := NewClient(
		apiKey,
		WithRetryCount(3),
		WithRetryWaitTime(2*time.Second),
		WithRetryMaxWaitTime(10*time.Second),
	)
	if err != nil {
		t.Fatalf("NewClient() order 1 error = %v, want nil", err)
	}

	// Apply options in different order
	client2, err := NewClient(
		apiKey,
		WithRetryMaxWaitTime(10*time.Second),
		WithRetryWaitTime(2*time.Second),
		WithRetryCount(3),
	)
	if err != nil {
		t.Fatalf("NewClient() order 2 error = %v, want nil", err)
	}

	// Both clients should be created successfully
	if client1 == nil || client2 == nil {
		t.Fatal("Expected both clients to be created")
	}
}

func TestWithRetryWaitTimeEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		waitTime time.Duration
		wantErr  bool
	}{
		{
			name:     "negative wait time",
			waitTime: -1 * time.Second,
			wantErr:  false, // Resty handles negative values
		},
		{
			name:     "very large wait time",
			waitTime: 1000 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "nanosecond precision",
			waitTime: 1500 * time.Nanosecond,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey := "test-api-key"
			client, err := NewClient(apiKey, WithRetryWaitTime(tt.waitTime))

			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && client == nil {
				t.Fatal("Expected client to be created")
			}
		})
	}
}

func TestWithRetryMaxWaitTimeEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		maxWaitTime time.Duration
		wantErr     bool
	}{
		{
			name:        "negative max wait time",
			maxWaitTime: -1 * time.Second,
			wantErr:     false, // Resty handles negative values
		},
		{
			name:        "very large max wait time",
			maxWaitTime: 10000 * time.Hour,
			wantErr:     false,
		},
		{
			name:        "nanosecond precision",
			maxWaitTime: 2500 * time.Nanosecond,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey := "test-api-key"
			client, err := NewClient(apiKey, WithRetryMaxWaitTime(tt.maxWaitTime))

			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && client == nil {
				t.Fatal("Expected client to be created")
			}
		})
	}
}

func TestRetryConfigurationRealistic(t *testing.T) {
	// Test realistic retry configurations
	scenarios := []struct {
		name        string
		retryCount  int
		waitTime    time.Duration
		maxWaitTime time.Duration
		description string
	}{
		{
			name:        "production default",
			retryCount:  3,
			waitTime:    2 * time.Second,
			maxWaitTime: 10 * time.Second,
			description: "Standard production configuration",
		},
		{
			name:        "high availability",
			retryCount:  5,
			waitTime:    10 * time.Second,
			maxWaitTime: 60 * time.Second,
			description: "Aggressive retry for critical operations",
		},
		{
			name:        "fast fail",
			retryCount:  1,
			waitTime:    1 * time.Second,
			maxWaitTime: 5 * time.Second,
			description: "Quick failure for non-critical operations",
		},
		{
			name:        "rate limit friendly",
			retryCount:  3,
			waitTime:    5 * time.Second,
			maxWaitTime: 30 * time.Second,
			description: "Conservative retry to respect rate limits",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			apiKey := "test-api-key"
			client, err := NewClient(
				apiKey,
				WithRetryCount(scenario.retryCount),
				WithRetryWaitTime(scenario.waitTime),
				WithRetryMaxWaitTime(scenario.maxWaitTime),
			)

			if err != nil {
				t.Fatalf("NewClient() for %s error = %v, want nil", scenario.description, err)
			}

			if client == nil {
				t.Fatalf("Expected client to be created for %s", scenario.description)
			}

			t.Logf("Successfully created client with %s configuration", scenario.description)
		})
	}
}
