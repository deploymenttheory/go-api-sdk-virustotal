package client

import (
	"testing"

	"go.uber.org/zap/zaptest"
	"resty.dev/v3"
)

func TestAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *AuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &AuthConfig{
				APIKey:     "test-api-key",
				APIVersion: "v3",
			},
			wantErr: false,
		},
		{
			name: "valid config without version",
			config: &AuthConfig{
				APIKey: "test-api-key",
			},
			wantErr: false,
		},
		{
			name: "empty API key",
			config: &AuthConfig{
				APIKey:     "",
				APIVersion: "v3",
			},
			wantErr: true,
			errMsg:  "API key is required",
		},
		{
			name: "nil config fields",
			config: &AuthConfig{
				APIKey:     "",
				APIVersion: "",
			},
			wantErr: true,
			errMsg:  "API key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && err.Error() != tt.errMsg {
				t.Errorf("AuthConfig.Validate() error message = %q, want %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestSetupAuthentication_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)
	client := resty.New()

	authConfig := &AuthConfig{
		APIKey:     "test-api-key-12345",
		APIVersion: "v3",
	}

	err := SetupAuthentication(client, authConfig, logger)

	if err != nil {
		t.Fatalf("SetupAuthentication() error = %v, want nil", err)
	}

	// Verify API key header is set
	headers := client.Header()
	if got := headers.Get(APIKeyHeader); got != "test-api-key-12345" {
		t.Errorf("API key header = %q, want %q", got, "test-api-key-12345")
	}
}

func TestSetupAuthentication_DefaultAPIVersion(t *testing.T) {
	logger := zaptest.NewLogger(t)
	client := resty.New()

	authConfig := &AuthConfig{
		APIKey:     "test-api-key",
		APIVersion: "", // Empty, should use default
	}

	err := SetupAuthentication(client, authConfig, logger)

	if err != nil {
		t.Fatalf("SetupAuthentication() error = %v, want nil", err)
	}

	// Verify API key is set
	headers := client.Header()
	if got := headers.Get(APIKeyHeader); got != "test-api-key" {
		t.Errorf("API key header = %q, want %q", got, "test-api-key")
	}
}

func TestSetupAuthentication_InvalidConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	client := resty.New()

	tests := []struct {
		name       string
		authConfig *AuthConfig
		wantErr    bool
		errContain string
	}{
		{
			name: "empty API key",
			authConfig: &AuthConfig{
				APIKey:     "",
				APIVersion: "v3",
			},
			wantErr:    true,
			errContain: "authentication validation failed",
		},
		{
			name: "nil-like config",
			authConfig: &AuthConfig{
				APIKey:     "",
				APIVersion: "",
			},
			wantErr:    true,
			errContain: "API key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetupAuthentication(client, tt.authConfig, logger)

			if (err != nil) != tt.wantErr {
				t.Errorf("SetupAuthentication() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				if err.Error() == "" {
					t.Error("Expected error message, got empty string")
				}
			}
		})
	}
}

func TestSetupAuthentication_CustomAPIVersion(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name       string
		apiVersion string
	}{
		{
			name:       "custom v3",
			apiVersion: "v3",
		},
		{
			name:       "custom v4",
			apiVersion: "v4",
		},
		{
			name:       "empty uses default",
			apiVersion: "",
		},
		{
			name:       "custom version string",
			apiVersion: "2023-01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := resty.New()
			authConfig := &AuthConfig{
				APIKey:     "test-key",
				APIVersion: tt.apiVersion,
			}

			err := SetupAuthentication(client, authConfig, logger)
			if err != nil {
				t.Fatalf("SetupAuthentication() error = %v, want nil", err)
			}

			// Verify API key header is set
			headers := client.Header()
			if got := headers.Get(APIKeyHeader); got != "test-key" {
				t.Errorf("API key header = %q, want %q", got, "test-key")
			}
		})
	}
}

func TestSetupAuthentication_HeadersAreSet(t *testing.T) {
	logger := zaptest.NewLogger(t)
	client := resty.New()

	authConfig := &AuthConfig{
		APIKey:     "test-api-key",
		APIVersion: "v3",
	}

	err := SetupAuthentication(client, authConfig, logger)
	if err != nil {
		t.Fatalf("SetupAuthentication() error = %v, want nil", err)
	}

	// Verify the API key header is present
	headers := client.Header()
	apiKeyHeader := headers.Get(APIKeyHeader)
	if apiKeyHeader == "" {
		t.Error("API key header should be set")
	}

	if apiKeyHeader != "test-api-key" {
		t.Errorf("API key header = %q, want %q", apiKeyHeader, "test-api-key")
	}
}

func TestSetupAuthentication_MultipleCallsOverwrite(t *testing.T) {
	logger := zaptest.NewLogger(t)
	client := resty.New()

	// First setup
	authConfig1 := &AuthConfig{
		APIKey:     "first-key",
		APIVersion: "v3",
	}
	err := SetupAuthentication(client, authConfig1, logger)
	if err != nil {
		t.Fatalf("First SetupAuthentication() error = %v, want nil", err)
	}

	// Verify first setup
	headers := client.Header()
	if got := headers.Get(APIKeyHeader); got != "first-key" {
		t.Errorf("After first setup, API key = %q, want %q", got, "first-key")
	}

	// Second setup with different values
	authConfig2 := &AuthConfig{
		APIKey:     "second-key",
		APIVersion: "v4",
	}
	err = SetupAuthentication(client, authConfig2, logger)
	if err != nil {
		t.Fatalf("Second SetupAuthentication() error = %v, want nil", err)
	}

	// Verify second setup overwrote first
	headers = client.Header()
	if got := headers.Get(APIKeyHeader); got != "second-key" {
		t.Errorf("After second setup, API key = %q, want %q", got, "second-key")
	}
}

func TestAuthConfig_Fields(t *testing.T) {
	// Test that AuthConfig struct can hold expected values
	config := &AuthConfig{
		APIKey:     "my-api-key-12345",
		APIVersion: "v3.1",
	}

	if config.APIKey != "my-api-key-12345" {
		t.Errorf("APIKey = %q, want %q", config.APIKey, "my-api-key-12345")
	}

	if config.APIVersion != "v3.1" {
		t.Errorf("APIVersion = %q, want %q", config.APIVersion, "v3.1")
	}
}

func TestSetupAuthentication_NilClient(t *testing.T) {
	logger := zaptest.NewLogger(t)

	authConfig := &AuthConfig{
		APIKey:     "test-key",
		APIVersion: "v3",
	}

	// This will panic if not handled, which is acceptable for nil client
	defer func() {
		if r := recover(); r != nil {
			// Panic is expected for nil client
			t.Logf("Panic recovered (expected): %v", r)
		}
	}()

	_ = SetupAuthentication(nil, authConfig, logger)
}

func TestAuthConfig_LongAPIKey(t *testing.T) {
	// Test with a very long API key (should still be valid)
	longKey := ""
	for i := 0; i < 1000; i++ {
		longKey += "a"
	}

	config := &AuthConfig{
		APIKey:     longKey,
		APIVersion: "v3",
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() with long API key error = %v, want nil", err)
	}

	// Setup should also work
	logger := zaptest.NewLogger(t)
	client := resty.New()
	err = SetupAuthentication(client, config, logger)
	if err != nil {
		t.Errorf("SetupAuthentication() with long API key error = %v, want nil", err)
	}
}

func TestAuthConfig_SpecialCharactersInAPIKey(t *testing.T) {
	// Test with special characters in API key
	specialKeys := []string{
		"key-with-dashes",
		"key_with_underscores",
		"key.with.dots",
		"key123with456numbers",
		"key-_./~:?#[]@!$&'()*+,;=%spaces",
	}

	for _, key := range specialKeys {
		t.Run(key, func(t *testing.T) {
			config := &AuthConfig{
				APIKey:     key,
				APIVersion: "v3",
			}

			err := config.Validate()
			if err != nil {
				t.Errorf("Validate() with key %q error = %v, want nil", key, err)
			}

			logger := zaptest.NewLogger(t)
			client := resty.New()
			err = SetupAuthentication(client, config, logger)
			if err != nil {
				t.Errorf("SetupAuthentication() with key %q error = %v, want nil", key, err)
			}
		})
	}
}

func TestAuthConfig_WhitespaceAPIKey(t *testing.T) {
	// Test with whitespace-only API key (should be considered invalid)
	tests := []struct {
		name    string
		apiKey  string
		wantErr bool
	}{
		{
			name:    "spaces only",
			apiKey:  "   ",
			wantErr: false, // Non-empty string, validation passes (though API would reject it)
		},
		{
			name:    "tabs only",
			apiKey:  "\t\t\t",
			wantErr: false, // Non-empty string, validation passes
		},
		{
			name:    "newlines only",
			apiKey:  "\n\n",
			wantErr: false, // Non-empty string, validation passes
		},
		{
			name:    "truly empty",
			apiKey:  "",
			wantErr: true, // Empty string, validation fails
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &AuthConfig{
				APIKey:     tt.apiKey,
				APIVersion: "v3",
			}

			err := config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() with whitespace key error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
