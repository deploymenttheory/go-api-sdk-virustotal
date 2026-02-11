package code_insights

import (
	"encoding/base64"
	"testing"
)

func TestValidateBase64(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		wantErr bool
		errMsg  string
	}{
		// Valid cases
		{
			name:    "valid base64 simple text",
			encoded: base64.StdEncoding.EncodeToString([]byte("Hello, World!")),
			wantErr: false,
		},
		{
			name:    "valid base64 code block",
			encoded: base64.StdEncoding.EncodeToString([]byte("int main() { return 0; }")),
			wantErr: false,
		},
		{
			name:    "valid base64 with padding",
			encoded: "SGVsbG8gV29ybGQ=",
			wantErr: false,
		},
		{
			name:    "valid base64 without padding needs",
			encoded: "SGVsbG8=",
			wantErr: false,
		},
		{
			name:    "valid base64 multiline code",
			encoded: base64.StdEncoding.EncodeToString([]byte("int main() {\n    printf(\"test\");\n    return 0;\n}")),
			wantErr: false,
		},
		// Invalid cases
		{
			name:    "empty string",
			encoded: "",
			wantErr: true,
			errMsg:  "base64 string cannot be empty",
		},
		{
			name:    "invalid base64 characters",
			encoded: "Hello@World!",
			wantErr: true,
			errMsg:  "invalid base64 encoding",
		},
		{
			name:    "invalid base64 wrong padding",
			encoded: "SGVsbG8gV29ybGQ==",
			wantErr: true,
			errMsg:  "invalid base64 encoding",
		},
		{
			name:    "plain text not encoded",
			encoded: "This is not base64 encoded!",
			wantErr: true,
			errMsg:  "invalid base64 encoding",
		},
		{
			name:    "base64 with spaces",
			encoded: "SGVs bG8g V29y bGQ=",
			wantErr: true,
			errMsg:  "invalid base64 encoding",
		},
		{
			name:    "incomplete base64",
			encoded: "SGVsbG8",
			wantErr: true,
			errMsg:  "invalid base64 encoding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBase64(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateBase64() error message = %v, should contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestValidateCodeType(t *testing.T) {
	tests := []struct {
		name     string
		codeType string
		wantErr  bool
		errMsg   string
	}{
		// Valid cases
		{
			name:     "valid disassembled",
			codeType: "disassembled",
			wantErr:  false,
		},
		{
			name:     "valid decompiled",
			codeType: "decompiled",
			wantErr:  false,
		},
		{
			name:     "valid disassembled constant",
			codeType: CodeTypeDisassembled,
			wantErr:  false,
		},
		{
			name:     "valid decompiled constant",
			codeType: CodeTypeDecompiled,
			wantErr:  false,
		},
		// Invalid cases
		{
			name:     "empty code type",
			codeType: "",
			wantErr:  true,
			errMsg:   "code type cannot be empty",
		},
		{
			name:     "invalid uppercase",
			codeType: "DISASSEMBLED",
			wantErr:  true,
			errMsg:   "code type must be one of",
		},
		{
			name:     "invalid mixed case",
			codeType: "Decompiled",
			wantErr:  true,
			errMsg:   "code type must be one of",
		},
		{
			name:     "invalid type",
			codeType: "assembly",
			wantErr:  true,
			errMsg:   "code type must be one of",
		},
		{
			name:     "invalid type compiled",
			codeType: "compiled",
			wantErr:  true,
			errMsg:   "code type must be one of",
		},
		{
			name:     "invalid type with spaces",
			codeType: "dis assembled",
			wantErr:  true,
			errMsg:   "code type must be one of",
		},
		{
			name:     "invalid type with trailing space",
			codeType: "disassembled ",
			wantErr:  true,
			errMsg:   "code type must be one of",
		},
		{
			name:     "invalid type with leading space",
			codeType: " disassembled",
			wantErr:  true,
			errMsg:   "code type must be one of",
		},
		{
			name:     "numeric value",
			codeType: "123",
			wantErr:  true,
			errMsg:   "code type must be one of",
		},
		{
			name:     "special characters",
			codeType: "dis@ssembled",
			wantErr:  true,
			errMsg:   "code type must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCodeType(tt.codeType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCodeType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateCodeType() error message = %v, should contain %v", err.Error(), tt.errMsg)
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
