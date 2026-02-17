package client

import (
	"fmt"
	"sync"
	"testing"
	"time"

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
			name: "valid config with custom token settings",
			config: &AuthConfig{
				APIKey:           "test-api-key",
				APIVersion:       "v3",
				TokenLifetime:    3600 * time.Second,
				RefreshThreshold: 300 * time.Second,
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
		{
			name: "token lifetime too short",
			config: &AuthConfig{
				APIKey:        "test-key",
				TokenLifetime: 30 * time.Second, // Less than MinimumRefreshThreshold
			},
			wantErr: true,
		},
		{
			name: "refresh threshold >= token lifetime",
			config: &AuthConfig{
				APIKey:           "test-key",
				TokenLifetime:    600 * time.Second,
				RefreshThreshold: 600 * time.Second, // Same as lifetime
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

func TestNewTokenManager(t *testing.T) {
	logger := zaptest.NewLogger(t)

	refreshFunc := func(apiKey string) (string, time.Time, error) {
		return "test-token", time.Now().Add(1 * time.Hour), nil
	}

	authConfig := &AuthConfig{
		APIKey:     "test-api-key",
		APIVersion: "v3",
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	if tm == nil {
		t.Fatal("NewTokenManager() returned nil")
	}

	if tm.authConfig.TokenLifetime != DefaultTokenLifetime {
		t.Errorf("TokenLifetime = %v, want %v", tm.authConfig.TokenLifetime, DefaultTokenLifetime)
	}

	if tm.authConfig.RefreshThreshold != DefaultRefreshThreshold {
		t.Errorf("RefreshThreshold = %v, want %v", tm.authConfig.RefreshThreshold, DefaultRefreshThreshold)
	}
}

func TestTokenManager_GetToken_InitialAcquisition(t *testing.T) {
	logger := zaptest.NewLogger(t)

	expectedToken := "initial-token-12345"
	expiresAt := time.Now().Add(1 * time.Hour)

	refreshFunc := func(apiKey string) (string, time.Time, error) {
		return expectedToken, expiresAt, nil
	}

	authConfig := &AuthConfig{
		APIKey:     "test-api-key",
		APIVersion: "v3",
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	token, err := tm.GetToken()
	if err != nil {
		t.Fatalf("GetToken() error = %v, want nil", err)
	}

	if token != expectedToken {
		t.Errorf("GetToken() = %q, want %q", token, expectedToken)
	}
}

func TestTokenManager_GetToken_ReusesCachedToken(t *testing.T) {
	logger := zaptest.NewLogger(t)

	callCount := 0
	refreshFunc := func(apiKey string) (string, time.Time, error) {
		callCount++
		return fmt.Sprintf("token-%d", callCount), time.Now().Add(1 * time.Hour), nil
	}

	authConfig := &AuthConfig{
		APIKey:           "test-api-key",
		TokenLifetime:    3600 * time.Second,
		RefreshThreshold: 300 * time.Second,
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	// First call should refresh
	token1, err := tm.GetToken()
	if err != nil {
		t.Fatalf("GetToken() first call error = %v", err)
	}

	if callCount != 1 {
		t.Errorf("refreshFunc call count after first GetToken = %d, want 1", callCount)
	}

	// Second call should reuse cached token
	token2, err := tm.GetToken()
	if err != nil {
		t.Fatalf("GetToken() second call error = %v", err)
	}

	if callCount != 1 {
		t.Errorf("refreshFunc call count after second GetToken = %d, want 1 (should reuse cache)", callCount)
	}

	if token1 != token2 {
		t.Errorf("GetToken() returned different tokens: %q vs %q", token1, token2)
	}
}

func TestTokenManager_GetToken_RefreshesExpiredToken(t *testing.T) {
	logger := zaptest.NewLogger(t)

	callCount := 0
	refreshFunc := func(apiKey string) (string, time.Time, error) {
		callCount++
		// Short lifetime for testing
		return fmt.Sprintf("token-%d", callCount), time.Now().Add(100 * time.Millisecond), nil
	}

	authConfig := &AuthConfig{
		APIKey:           "test-api-key",
		TokenLifetime:    100 * time.Millisecond,
		RefreshThreshold: 90 * time.Millisecond,
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	// First call
	token1, err := tm.GetToken()
	if err != nil {
		t.Fatalf("GetToken() first call error = %v", err)
	}

	// Wait for token to expire
	time.Sleep(150 * time.Millisecond)

	// Second call should refresh
	token2, err := tm.GetToken()
	if err != nil {
		t.Fatalf("GetToken() second call error = %v", err)
	}

	if callCount != 2 {
		t.Errorf("refreshFunc call count = %d, want 2", callCount)
	}

	if token1 == token2 {
		t.Error("GetToken() should have refreshed to a new token")
	}
}

func TestTokenManager_GetToken_RefreshError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	refreshFunc := func(apiKey string) (string, time.Time, error) {
		return "", time.Time{}, fmt.Errorf("refresh failed")
	}

	authConfig := &AuthConfig{
		APIKey: "test-api-key",
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	_, err := tm.GetToken()
	if err == nil {
		t.Fatal("GetToken() error = nil, want error")
	}

	if err.Error() != "token refresh failed: refresh failed" {
		t.Errorf("GetToken() error = %q, want refresh error", err.Error())
	}
}

func TestTokenManager_ForceRefresh(t *testing.T) {
	logger := zaptest.NewLogger(t)

	callCount := 0
	refreshFunc := func(apiKey string) (string, time.Time, error) {
		callCount++
		return fmt.Sprintf("token-%d", callCount), time.Now().Add(1 * time.Hour), nil
	}

	authConfig := &AuthConfig{
		APIKey: "test-api-key",
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	// Initial token
	token1, _ := tm.GetToken()

	// Force refresh
	err := tm.ForceRefresh()
	if err != nil {
		t.Fatalf("ForceRefresh() error = %v", err)
	}

	if callCount != 2 {
		t.Errorf("refreshFunc call count = %d, want 2", callCount)
	}

	// Get token again should return refreshed token
	token2, _ := tm.GetToken()

	if token1 == token2 {
		t.Error("Token should have been refreshed")
	}
}

func TestTokenManager_GetTokenInfo(t *testing.T) {
	logger := zaptest.NewLogger(t)

	expiresAt := time.Now().Add(1 * time.Hour)
	refreshFunc := func(apiKey string) (string, time.Time, error) {
		return "test-token", expiresAt, nil
	}

	authConfig := &AuthConfig{
		APIKey:           "test-api-key",
		RefreshThreshold: 300 * time.Second,
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	// Before getting token
	info := tm.GetTokenInfo()
	if info.HasToken {
		t.Error("GetTokenInfo().HasToken should be false before token acquired")
	}

	// After getting token
	tm.GetToken()
	info = tm.GetTokenInfo()

	if !info.HasToken {
		t.Error("GetTokenInfo().HasToken should be true after token acquired")
	}

	if info.TimeRemaining <= 0 {
		t.Error("GetTokenInfo().TimeRemaining should be > 0")
	}

	if info.RefreshThreshold != 300*time.Second {
		t.Errorf("GetTokenInfo().RefreshThreshold = %v, want 300s", info.RefreshThreshold)
	}
}

func TestTokenManager_GetAPIVersion(t *testing.T) {
	logger := zaptest.NewLogger(t)
	refreshFunc := func(apiKey string) (string, time.Time, error) {
		return "token", time.Now().Add(1 * time.Hour), nil
	}

	tests := []struct {
		name       string
		apiVersion string
		want       string
	}{
		{
			name:       "custom version",
			apiVersion: "v3",
			want:       "v3",
		},
		{
			name:       "empty uses default",
			apiVersion: "",
			want:       DefaultAPIVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authConfig := &AuthConfig{
				APIKey:     "test-key",
				APIVersion: tt.apiVersion,
			}

			tm := NewTokenManager(authConfig, logger, refreshFunc)
			got := tm.GetAPIVersion()

			if got != tt.want {
				t.Errorf("GetAPIVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetupAuthentication_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)
	transport := resty.New()

	refreshFunc := func(apiKey string) (string, time.Time, error) {
		return "test-token-" + apiKey, time.Now().Add(1 * time.Hour), nil
	}

	authConfig := &AuthConfig{
		APIKey:     "test-api-key-12345",
		APIVersion: "v3",
	}

	tokenManager, err := SetupAuthentication(transport, authConfig, logger, refreshFunc)

	if err != nil {
		t.Fatalf("SetupAuthentication() error = %v, want nil", err)
	}

	if tokenManager == nil {
		t.Fatal("Expected non-nil TokenManager")
	}

	// Verify token manager has acquired initial token
	info := tokenManager.GetTokenInfo()
	if !info.HasToken {
		t.Error("TokenManager should have acquired initial token")
	}
}

func TestSetupAuthentication_InvalidConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	transport := resty.New()

	refreshFunc := func(apiKey string) (string, time.Time, error) {
		return "token", time.Now().Add(1 * time.Hour), nil
	}

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
		{
			name: "invalid token lifetime",
			authConfig: &AuthConfig{
				APIKey:        "test-key",
				TokenLifetime: 30 * time.Second,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenManager, err := SetupAuthentication(transport, tt.authConfig, logger, refreshFunc)

			if (err != nil) != tt.wantErr {
				t.Errorf("SetupAuthentication() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tokenManager != nil {
				t.Error("Expected nil TokenManager on error")
			}
		})
	}
}

func TestSetupAuthentication_InitialTokenFailure(t *testing.T) {
	logger := zaptest.NewLogger(t)
	transport := resty.New()

	refreshFunc := func(apiKey string) (string, time.Time, error) {
		return "", time.Time{}, fmt.Errorf("initial token acquisition failed")
	}

	authConfig := &AuthConfig{
		APIKey:     "test-api-key",
		APIVersion: "v3",
	}

	_, err := SetupAuthentication(transport, authConfig, logger, refreshFunc)

	if err == nil {
		t.Fatal("SetupAuthentication() error = nil, want error for initial token failure")
	}
}

// Thread-safety tests

func TestTokenManager_ConcurrentGetToken(t *testing.T) {
	logger := zaptest.NewLogger(t)

	callCount := 0
	var mu sync.Mutex
	refreshFunc := func(apiKey string) (string, time.Time, error) {
		mu.Lock()
		callCount++
		mu.Unlock()
		// Simulate some delay in token acquisition
		time.Sleep(10 * time.Millisecond)
		return "concurrent-token", time.Now().Add(1 * time.Hour), nil
	}

	authConfig := &AuthConfig{
		APIKey: "test-api-key",
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	// Run 100 concurrent GetToken calls
	const numGoroutines = 100
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	tokens := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := tm.GetToken()
			if err != nil {
				errors <- err
				return
			}
			tokens <- token
		}()
	}

	wg.Wait()
	close(errors)
	close(tokens)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent GetToken() error: %v", err)
	}

	// Verify all tokens are the same (cached)
	tokenSet := make(map[string]bool)
	for token := range tokens {
		tokenSet[token] = true
	}

	if len(tokenSet) != 1 {
		t.Errorf("Expected all goroutines to get same cached token, got %d different tokens", len(tokenSet))
	}

	// Should have only called refresh once (other goroutines waited)
	mu.Lock()
	defer mu.Unlock()
	if callCount != 1 {
		t.Errorf("refreshFunc call count = %d, want 1 (should cache for concurrent calls)", callCount)
	}
}

func TestTokenManager_ConcurrentRefresh(t *testing.T) {
	logger := zaptest.NewLogger(t)

	var callCount int
	var mu sync.Mutex
	refreshFunc := func(apiKey string) (string, time.Time, error) {
		mu.Lock()
		callCount++
		count := callCount
		mu.Unlock()
		return fmt.Sprintf("token-%d", count), time.Now().Add(1 * time.Hour), nil
	}

	authConfig := &AuthConfig{
		APIKey: "test-api-key",
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	// Get initial token
	tm.GetToken()

	// Concurrent force refreshes
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := tm.ForceRefresh()
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent ForceRefresh() error: %v", err)
	}

	// Verify final token is valid
	token, err := tm.GetToken()
	if err != nil {
		t.Errorf("GetToken() after concurrent refreshes error: %v", err)
	}
	if token == "" {
		t.Error("Token should not be empty after concurrent refreshes")
	}
}

func TestTokenManager_MinimumRefreshThreshold(t *testing.T) {
	logger := zaptest.NewLogger(t)

	refreshFunc := func(apiKey string) (string, time.Time, error) {
		return "token", time.Now().Add(1 * time.Hour), nil
	}

	// Try to set refresh threshold below minimum
	authConfig := &AuthConfig{
		APIKey:           "test-key",
		TokenLifetime:    3600 * time.Second,
		RefreshThreshold: 30 * time.Second, // Below MinimumRefreshThreshold
	}

	tm := NewTokenManager(authConfig, logger, refreshFunc)

	// Should be adjusted to minimum
	if tm.authConfig.RefreshThreshold != MinimumRefreshThreshold {
		t.Errorf("RefreshThreshold = %v, want %v (should be adjusted to minimum)",
			tm.authConfig.RefreshThreshold, MinimumRefreshThreshold)
	}
}

func TestAuthConfig_Fields(t *testing.T) {
	config := &AuthConfig{
		APIKey:           "my-api-key-12345",
		APIVersion:       "v3.1",
		TokenLifetime:    3600 * time.Second,
		RefreshThreshold: 300 * time.Second,
	}

	if config.APIKey != "my-api-key-12345" {
		t.Errorf("APIKey = %q, want %q", config.APIKey, "my-api-key-12345")
	}

	if config.APIVersion != "v3.1" {
		t.Errorf("APIVersion = %q, want %q", config.APIVersion, "v3.1")
	}

	if config.TokenLifetime != 3600*time.Second {
		t.Errorf("TokenLifetime = %v, want 3600s", config.TokenLifetime)
	}

	if config.RefreshThreshold != 300*time.Second {
		t.Errorf("RefreshThreshold = %v, want 300s", config.RefreshThreshold)
	}
}
