package search_and_metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateSearchQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid query",
			query:   "type:peexe",
			wantErr: false,
		},
		{
			name:    "Valid hash query",
			query:   "44d88612fea8a8f36de82e1278abb02f",
			wantErr: false,
		},
		{
			name:    "Valid content query",
			query:   "content:\"hello world\"",
			wantErr: false,
		},
		{
			name:    "Empty query",
			query:   "",
			wantErr: true,
			errMsg:  "search query cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSearchQuery(tt.query)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSnippetID(t *testing.T) {
	tests := []struct {
		name      string
		snippetID string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "Valid snippet ID",
			snippetID: "L3Z0c2FtcGxlcy8zODIzMzkzNjNhOTM2NDM2ZDM2MDM1MzFkM2IzOGEzMmUzMTUzNzM3MTM4MzY3MzBlM2Q2MzQ4MzY1M2MzYzNh",
			wantErr:   false,
		},
		{
			name:      "Empty snippet ID",
			snippetID: "",
			wantErr:   true,
			errMsg:    "snippet ID cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSnippetID(tt.snippetID)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
