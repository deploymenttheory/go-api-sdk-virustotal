package urls

import (
	"strings"
	"testing"
)

func TestValidateURLID(t *testing.T) {
	tests := []struct {
		name    string
		urlID   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty string",
			urlID:   "",
			wantErr: true,
			errMsg:  "URL ID cannot be empty",
		},
		{
			name:    "valid SHA-256 lowercase",
			urlID:   "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			wantErr: false,
		},
		{
			name:    "valid SHA-256 uppercase",
			urlID:   "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
			wantErr: false,
		},
		{
			name:    "valid SHA-256 mixed case",
			urlID:   "1234567890AbCdEf1234567890aBcDeF1234567890AbCdEf1234567890aBcDeF",
			wantErr: false,
		},
		{
			name:    "valid hex string (not SHA-256 length but valid base64)",
			urlID:   "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde",
			wantErr: false,
			errMsg:  "",
		},
		{
			name:    "valid hex string (longer than SHA-256 but valid base64)",
			urlID:   "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef0",
			wantErr: false,
			errMsg:  "",
		},
		{
			name:    "invalid string with 'g' character",
			urlID:   "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeg",
			wantErr: false,
			errMsg:  "",
		},
		{
			name:    "valid unpadded base64",
			urlID:   "aHR0cDovL3d3dy5leGFtcGxlLmNvbQ",
			wantErr: false,
		},
		{
			name:    "valid unpadded base64 with hyphen",
			urlID:   "aHR0cDovL3d3dy5leGFtcGxlLmNvbS90ZXN0LXBhdGg",
			wantErr: false,
		},
		{
			name:    "valid unpadded base64 with underscore",
			urlID:   "aHR0cDovL3d3dy5leGFtcGxlLmNvbS90ZXN0X3BhdGg",
			wantErr: false,
		},
		{
			name:    "invalid padded base64",
			urlID:   "aHR0cDovL3d3dy5leGFtcGxlLmNvbQ==",
			wantErr: true,
			errMsg:  "padding character '=' is not allowed",
		},
		{
			name:    "invalid padded base64 single padding",
			urlID:   "aHR0cDovL3d3dy5leGFtcGxlLmNvbQ=",
			wantErr: true,
			errMsg:  "padding character '=' is not allowed",
		},
		{
			name:    "invalid base64 with plus sign",
			urlID:   "aHR0cDovL3d3dy5leGFtcGxlLmNvbQ+test",
			wantErr: true,
			errMsg:  "must be either a SHA-256 hash",
		},
		{
			name:    "invalid base64 with slash",
			urlID:   "aHR0cDovL3d3dy5leGFtcGxlLmNvbQ/test",
			wantErr: true,
			errMsg:  "must be either a SHA-256 hash",
		},
		{
			name:    "valid long base64",
			urlID:   "aHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20vZ3VpL2hvbWUvdXBsb2Fk",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURLID(tt.urlID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateURLID() expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateURLID() error = %v, want error containing %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateURLID() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestValidateURLID_RealWorldExamples tests with real-world style URL identifiers
func TestValidateURLID_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name    string
		urlID   string
		wantErr bool
	}{
		{
			name:    "real SHA-256 example",
			urlID:   "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
			wantErr: false,
		},
		{
			name:    "real base64 example - google.com",
			urlID:   "aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQ",
			wantErr: false,
		},
		{
			name:    "real base64 example - with path and query",
			urlID:   "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vcGF0aC90by9yZXNvdXJjZT9xdWVyeT12YWx1ZQ",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURLID(tt.urlID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURLID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
