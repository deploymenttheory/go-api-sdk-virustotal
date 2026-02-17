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
	}{
		{
			name: "valid config with defaults",
			config: &AuthConfig{
				APIKey:     "test-api-key",
				APIVersion: "v3",
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
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

	// Verify the x-apikey header is set
	headers := client.Header()
	apiKey := headers.Get("x-apikey")
	if apiKey != "test-api-key-12345" {
		t.Errorf("x-apikey header = %q, want %q", apiKey, "test-api-key-12345")
	}
}

func TestSetupAuthentication_InvalidConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	client := resty.New()

	tests := []struct {
		name       string
		authConfig *AuthConfig
		wantErr    bool
	}{
		{
			name: "empty API key",
			authConfig: &AuthConfig{
				APIKey:     "",
				APIVersion: "v3",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetupAuthentication(client, tt.authConfig, logger)

			if (err != nil) != tt.wantErr {
				t.Errorf("SetupAuthentication() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestAuthConfig_Fields(t *testing.T) {
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
