package comments

import (
	"testing"
)

func TestValidateCommentID(t *testing.T) {
	tests := []struct {
		name      string
		commentID string
		wantErr   bool
		errMsg    string
	}{
		// Valid cases
		{
			name:      "valid domain comment ID",
			commentID: "d-example.com-abc12345",
			wantErr:   false,
		},
		{
			name:      "valid file comment ID",
			commentID: "f-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-def67890",
			wantErr:   false,
		},
		{
			name:      "valid graph comment ID",
			commentID: "g-graphid123-xyz98765",
			wantErr:   false,
		},
		{
			name:      "valid IP comment ID",
			commentID: "i-8.8.8.8-qwe45678",
			wantErr:   false,
		},
		{
			name:      "valid URL comment ID",
			commentID: "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-rst13579",
			wantErr:   false,
		},
		{
			name:      "valid comment ID with multiple dashes in item ID",
			commentID: "d-sub-domain.example.com-random123",
			wantErr:   false,
		},
		// Invalid cases
		{
			name:      "empty comment ID",
			commentID: "",
			wantErr:   true,
			errMsg:    "comment ID cannot be empty",
		},
		{
			name:      "invalid prefix",
			commentID: "x-example.com-abc12345",
			wantErr:   true,
			errMsg:    "comment ID must be in format",
		},
		{
			name:      "missing random string",
			commentID: "d-example.com",
			wantErr:   true,
			errMsg:    "comment ID must be in format",
		},
		{
			name:      "missing item ID",
			commentID: "d--abc12345",
			wantErr:   true, // Fails regex because .+ requires at least one character
			errMsg:    "comment ID must be in format",
		},
		{
			name:      "no dashes",
			commentID: "dexamplecomabc12345",
			wantErr:   true,
			errMsg:    "comment ID must be in format",
		},
		{
			name:      "uppercase prefix",
			commentID: "D-example.com-abc12345",
			wantErr:   true,
			errMsg:    "comment ID must be in format",
		},
		{
			name:      "numeric prefix",
			commentID: "1-example.com-abc12345",
			wantErr:   true,
			errMsg:    "comment ID must be in format",
		},
		{
			name:      "only prefix and dash",
			commentID: "d-",
			wantErr:   true,
			errMsg:    "comment ID must be in format",
		},
		{
			name:      "prefix with one part",
			commentID: "d-onlyonepart",
			wantErr:   true,
			errMsg:    "comment ID must be in format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommentID(tt.commentID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommentID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateCommentID() error message = %v, should contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
