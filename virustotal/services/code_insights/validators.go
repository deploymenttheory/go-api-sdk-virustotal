package code_insights

import (
	"encoding/base64"
	"fmt"
	"slices"
)

// ValidateBase64 validates that a string is valid base64 encoding
//
// Returns an error if the string is not valid base64
func ValidateBase64(encoded string) error {
	if encoded == "" {
		return fmt.Errorf("base64 string cannot be empty")
	}

	_, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("invalid base64 encoding: %w", err)
	}

	return nil
}

// ValidateCodeType validates that a code type is one of the supported types
//
// Supported types:
//  - "disassembled" for disassembled code
//  - "decompiled" for decompiled code
//
// Returns an error if the code type is invalid
func ValidateCodeType(codeType string) error {
	if codeType == "" {
		return fmt.Errorf("code type cannot be empty")
	}

	validTypes := []string{CodeTypeDisassembled, CodeTypeDecompiled}

	if !slices.Contains(validTypes, codeType) {
		return fmt.Errorf("code type must be one of: disassembled, decompiled")
	}

	return nil
}
