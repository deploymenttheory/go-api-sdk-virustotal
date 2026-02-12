package saved_searches

import (
	"testing"
)

func TestValidateSavedSearchID(t *testing.T) {
	tests := []struct {
		name     string
		searchID string
		wantErr  bool
		errMsg   string
	}{
		// Valid cases
		{
			name:     "valid search ID lowercase",
			searchID: "0a49acd622a44982b1986984ba31c15b",
			wantErr:  false,
		},
		{
			name:     "valid search ID uppercase",
			searchID: "0A49ACD622A44982B1986984BA31C15B",
			wantErr:  false,
		},
		{
			name:     "valid search ID mixed case",
			searchID: "f60631d600b44a91a8b20cef8c77aeac",
			wantErr:  false,
		},
		{
			name:     "valid search ID all zeros",
			searchID: "00000000000000000000000000000000",
			wantErr:  false,
		},
		{
			name:     "valid search ID all fs",
			searchID: "ffffffffffffffffffffffffffffffff",
			wantErr:  false,
		},
		// Invalid cases
		{
			name:     "empty search ID",
			searchID: "",
			wantErr:  true,
			errMsg:   "saved search ID cannot be empty",
		},
		{
			name:     "too short",
			searchID: "0a49acd622a44982b1986984ba31c1",
			wantErr:  true,
			errMsg:   "32-character hexadecimal",
		},
		{
			name:     "too long",
			searchID: "0a49acd622a44982b1986984ba31c15b1",
			wantErr:  true,
			errMsg:   "32-character hexadecimal",
		},
		{
			name:     "contains invalid characters",
			searchID: "0a49acd622a44982b1986984ba31c1zz",
			wantErr:  true,
			errMsg:   "32-character hexadecimal",
		},
		{
			name:     "contains spaces",
			searchID: "0a49acd622a44982 b1986984ba31c15b",
			wantErr:  true,
			errMsg:   "32-character hexadecimal",
		},
		{
			name:     "contains dashes",
			searchID: "0a49acd6-22a4-4982-b198-6984ba31c15b",
			wantErr:  true,
			errMsg:   "32-character hexadecimal",
		},
		{
			name:     "contains special characters",
			searchID: "0a49acd622a44982b1986984ba31c1@#",
			wantErr:  true,
			errMsg:   "32-character hexadecimal",
		},
		{
			name:     "numeric only",
			searchID: "01234567890123456789012345678901",
			wantErr:  false,
		},
	}

for _, tt := range tests {
	t.Run(tt.name, func(t *testing.T) {
		err := ValidateSavedSearchID(tt.searchID)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateSavedSearchID() error = %v, wantErr %v", err, tt.wantErr)
			return
		}
		if err != nil && tt.errMsg != "" {
			if !contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateSavedSearchID() error message = %v, should contain %v", err.Error(), tt.errMsg)
			}
		}
	})
}
}

func TestValidateAccessType(t *testing.T) {
	tests := []struct {
		name       string
		accessType string
		wantErr    bool
		errMsg     string
	}{
		// Valid cases
		{
			name:       "valid viewers",
			accessType: "viewers",
			wantErr:    false,
		},
		{
			name:       "valid editors",
			accessType: "editors",
			wantErr:    false,
		},
		{
			name:       "valid viewers constant",
			accessType: AccessTypeViewers,
			wantErr:    false,
		},
		{
			name:       "valid editors constant",
			accessType: AccessTypeEditors,
			wantErr:    false,
		},
		// Invalid cases
		{
			name:       "empty access type",
			accessType: "",
			wantErr:    true,
			errMsg:     "access type cannot be empty",
		},
		{
			name:       "invalid uppercase",
			accessType: "VIEWERS",
			wantErr:    true,
			errMsg:     "access type must be one of",
		},
		{
			name:       "invalid mixed case",
			accessType: "Editors",
			wantErr:    true,
			errMsg:     "access type must be one of",
		},
		{
			name:       "invalid type",
			accessType: "admins",
			wantErr:    true,
			errMsg:     "access type must be one of",
		},
		{
			name:       "invalid type owner",
			accessType: "owner",
			wantErr:    true,
			errMsg:     "access type must be one of",
		},
		{
			name:       "with trailing space",
			accessType: "viewers ",
			wantErr:    true,
			errMsg:     "access type must be one of",
		},
		{
			name:       "with leading space",
			accessType: " editors",
			wantErr:    true,
			errMsg:     "access type must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAccessType(tt.accessType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAccessType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateAccessType() error message = %v, should contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestValidateObjectType(t *testing.T) {
	tests := []struct {
		name       string
		objectType string
		wantErr    bool
		errMsg     string
	}{
		// Valid cases
		{
			name:       "valid user",
			objectType: "user",
			wantErr:    false,
		},
		{
			name:       "valid group",
			objectType: "group",
			wantErr:    false,
		},
		{
			name:       "valid user constant",
			objectType: ObjectTypeUser,
			wantErr:    false,
		},
		{
			name:       "valid group constant",
			objectType: ObjectTypeGroup,
			wantErr:    false,
		},
		// Invalid cases
		{
			name:       "empty object type",
			objectType: "",
			wantErr:    true,
			errMsg:     "object type cannot be empty",
		},
		{
			name:       "invalid uppercase",
			objectType: "USER",
			wantErr:    true,
			errMsg:     "object type must be one of",
		},
		{
			name:       "invalid mixed case",
			objectType: "Group",
			wantErr:    true,
			errMsg:     "object type must be one of",
		},
		{
			name:       "invalid type",
			objectType: "admin",
			wantErr:    true,
			errMsg:     "object type must be one of",
		},
		{
			name:       "invalid type organization",
			objectType: "organization",
			wantErr:    true,
			errMsg:     "object type must be one of",
		},
		{
			name:       "with trailing space",
			objectType: "user ",
			wantErr:    true,
			errMsg:     "object type must be one of",
		},
		{
			name:       "with leading space",
			objectType: " group",
			wantErr:    true,
			errMsg:     "object type must be one of",
		},
		{
			name:       "saved_search type",
			objectType: "saved_search",
			wantErr:    true,
			errMsg:     "object type must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateObjectType(tt.objectType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateObjectType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateObjectType() error message = %v, should contain %v", err.Error(), tt.errMsg)
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
