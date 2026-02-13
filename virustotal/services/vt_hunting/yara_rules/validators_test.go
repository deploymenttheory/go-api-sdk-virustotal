package yara_rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateYaraRuleID(t *testing.T) {
	tests := []struct {
		name    string
		ruleID  string
		wantErr bool
	}{
		{
			name:    "valid rule ID",
			ruleID:  "003e1c51ef|PK_AXA_fun",
			wantErr: false,
		},
		{
			name:    "empty rule ID",
			ruleID:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateYaraRuleID(tt.ruleID)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "YARA rule ID cannot be empty")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRelationship(t *testing.T) {
	tests := []struct {
		name         string
		relationship string
		wantErr      bool
	}{
		{
			name:         "valid files relationship",
			relationship: RelationshipFiles,
			wantErr:      false,
		},
		{
			name:         "empty relationship",
			relationship: "",
			wantErr:      true,
		},
		{
			name:         "invalid relationship",
			relationship: "invalid",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRelationship(tt.relationship)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
