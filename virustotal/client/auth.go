package client

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"resty.dev/v3"
)

// AuthConfig holds authentication configuration for the VirusTotal API
type AuthConfig struct {
	// APIKey is the VirusTotal API key (used for initial token generation)
	APIKey string

	// APIVersion is the API version
	APIVersion string

	// TokenLifetime is how long tokens are valid (defaults to DefaultTokenLifetime)
	TokenLifetime time.Duration

	// RefreshThreshold - refresh token if less than this time remains (defaults to DefaultRefreshThreshold)
	RefreshThreshold time.Duration
}

// TokenManager handles token lifecycle with automatic refresh
type TokenManager struct {
	authConfig *AuthConfig
	logger     *zap.Logger
	mu         sync.RWMutex

	// Token state
	currentToken    string
	tokenExpiresAt  time.Time
	tokenAcquiredAt time.Time

	// Token refresh function (injected)
	refreshFunc TokenRefreshFunc
}

// TokenRefreshFunc is called when a new token is needed
// Implementation should call VirusTotal's token endpoint
type TokenRefreshFunc func(apiKey string) (token string, expiresAt time.Time, err error)

// TokenInfo provides token metadata for monitoring and debugging
type TokenInfo struct {
	HasToken         bool
	ExpiresAt        time.Time
	AcquiredAt       time.Time
	TimeRemaining    time.Duration
	NeedsRefresh     bool
	RefreshThreshold time.Duration
}

// Validate checks if the auth configuration is valid and sets
// defaults for token lifetime and refresh threshold if not provided
func (a *AuthConfig) Validate() error {
	if a.APIKey == "" {
		return fmt.Errorf("API key is required")
	}

	if a.TokenLifetime == 0 {
		a.TokenLifetime = DefaultTokenLifetime
	}
	if a.RefreshThreshold == 0 {
		a.RefreshThreshold = DefaultRefreshThreshold
	}

	if a.TokenLifetime < MinimumRefreshThreshold {
		return fmt.Errorf("token lifetime must be at least %v", MinimumRefreshThreshold)
	}

	if a.RefreshThreshold >= a.TokenLifetime {
		return fmt.Errorf("refresh threshold (%v) must be less than token lifetime (%v)",
			a.RefreshThreshold, a.TokenLifetime)
	}

	return nil
}

// NewTokenManager creates a new token manager
func NewTokenManager(authConfig *AuthConfig, logger *zap.Logger, refreshFunc TokenRefreshFunc) *TokenManager {

	if authConfig.TokenLifetime == 0 {
		authConfig.TokenLifetime = DefaultTokenLifetime
	}
	if authConfig.RefreshThreshold == 0 {
		authConfig.RefreshThreshold = DefaultRefreshThreshold
	}

	if authConfig.RefreshThreshold < MinimumRefreshThreshold {
		logger.Warn("Refresh threshold too low, using minimum",
			zap.Duration("requested", authConfig.RefreshThreshold),
			zap.Duration("minimum", MinimumRefreshThreshold))
		authConfig.RefreshThreshold = MinimumRefreshThreshold
	}

	return &TokenManager{
		authConfig:  authConfig,
		logger:      logger,
		refreshFunc: refreshFunc,
	}
}

// GetToken returns a valid token, refreshing if necessary
func (tm *TokenManager) GetToken() (string, error) {
	tm.mu.RLock()

	if tm.isTokenValid() {
		token := tm.currentToken
		tm.mu.RUnlock()
		return token, nil
	}

	tm.mu.RUnlock()
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed)
	if tm.isTokenValid() {
		return tm.currentToken, nil
	}

	return tm.refreshToken()
}

// isTokenValid checks if token is still valid (must be called with lock held)
func (tm *TokenManager) isTokenValid() bool {
	if tm.currentToken == "" {
		return false
	}

	now := time.Now()
	timeRemaining := tm.tokenExpiresAt.Sub(now)

	// Token is valid if it hasn't expired and has enough time remaining
	return timeRemaining > tm.authConfig.RefreshThreshold
}

// refreshToken gets a new token (must be called with write lock held)
func (tm *TokenManager) refreshToken() (string, error) {
	tm.logger.Info("Refreshing authentication token",
		zap.Time("old_expires_at", tm.tokenExpiresAt))

	newToken, expiresAt, err := tm.refreshFunc(tm.authConfig.APIKey)
	if err != nil {
		tm.logger.Error("Failed to refresh token", zap.Error(err))
		return "", fmt.Errorf("token refresh failed: %w", err)
	}

	tm.currentToken = newToken
	tm.tokenExpiresAt = expiresAt
	tm.tokenAcquiredAt = time.Now()

	timeUntilExpiry := tm.tokenExpiresAt.Sub(tm.tokenAcquiredAt)
	tm.logger.Info("Token refreshed successfully",
		zap.Time("expires_at", tm.tokenExpiresAt),
		zap.Duration("lifetime", timeUntilExpiry))

	return newToken, nil
}

// ForceRefresh forces an immediate token refresh
func (tm *TokenManager) ForceRefresh() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	_, err := tm.refreshToken()
	return err
}

// GetTokenInfo returns current token metadata (for monitoring/debugging)
func (tm *TokenManager) GetTokenInfo() TokenInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	now := time.Now()
	remaining := tm.tokenExpiresAt.Sub(now)
	if remaining < 0 {
		remaining = 0
	}

	return TokenInfo{
		HasToken:         tm.currentToken != "",
		ExpiresAt:        tm.tokenExpiresAt,
		AcquiredAt:       tm.tokenAcquiredAt,
		TimeRemaining:    remaining,
		NeedsRefresh:     !tm.isTokenValid(),
		RefreshThreshold: tm.authConfig.RefreshThreshold,
	}
}

// GetAPIVersion returns the API version
func (tm *TokenManager) GetAPIVersion() string {
	if tm.authConfig.APIVersion == "" {
		return DefaultAPIVersion
	}
	return tm.authConfig.APIVersion
}

// SetupAuthentication configures the resty client with token-based authentication
func SetupAuthentication(client *resty.Client, authConfig *AuthConfig, logger *zap.Logger, refreshFunc TokenRefreshFunc) (*TokenManager, error) {
	if err := authConfig.Validate(); err != nil {
		logger.Error("Authentication validation failed", zap.Error(err))
		return nil, fmt.Errorf("authentication validation failed: %w", err)
	}

	tokenManager := NewTokenManager(authConfig, logger, refreshFunc)

	_, err := tokenManager.GetToken()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire initial token: %w", err)
	}

	// Add middleware to inject current valid token on every request
	client.AddRequestMiddleware(func(c *resty.Client, req *resty.Request) error {
		token, err := tokenManager.GetToken()
		if err != nil {
			logger.Error("Failed to get valid token for request", zap.Error(err))
			return fmt.Errorf("authentication failed: %w", err)
		}

		req.SetHeader("Authorization", "Bearer "+token)
		return nil
	})

	apiVersion := authConfig.APIVersion
	if apiVersion == "" {
		apiVersion = DefaultAPIVersion
	}

	logger.Info("Token-based authentication configured",
		zap.String("api_version", apiVersion),
		zap.Duration("token_lifetime", authConfig.TokenLifetime),
		zap.Duration("refresh_threshold", authConfig.RefreshThreshold))

	return tokenManager, nil
}
