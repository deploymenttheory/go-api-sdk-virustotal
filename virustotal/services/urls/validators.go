package urls

import (
	"fmt"
	"regexp"
)

// URL identifier patterns based on VirusTotal API documentation
// https://docs.virustotal.com/reference/url
var (
	// sha256Pattern matches a 64-character hex string (SHA-256 hash)
	sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

	// base64URLPattern matches unpadded base64 URL-safe encoding (RFC 4648 section 3.2)
	// Characters: A-Z, a-z, 0-9, -, _ (no padding '=')
	base64URLPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// ValidateURLID validates a URL identifier
//
// URL identifiers can be in two forms:
//  1. The SHA-256 of the canonized URL (64 hex characters)
//  2. The string resulting from encoding the URL in base64 without padding (RFC 4648 section 3.2)
//
// Returns an error if the identifier is invalid
func ValidateURLID(urlID string) error {
	if urlID == "" {
		return fmt.Errorf("URL ID cannot be empty")
	}

	// Check for padding characters (not allowed)
	for i := 0; i < len(urlID); i++ {
		if urlID[i] == '=' {
			return fmt.Errorf("URL ID must be unpadded base64 (RFC 4648 section 3.2), padding character '=' is not allowed")
		}
	}

	// Check if it's a SHA-256 hash (64 hex characters)
	if sha256Pattern.MatchString(urlID) {
		return nil
	}

	// Check if it's a valid unpadded base64 URL-safe string
	// Note: This is permissive by design - any string with valid base64 URL-safe characters
	// is accepted (including hex strings that aren't exactly 64 chars, which is valid)
	if base64URLPattern.MatchString(urlID) {
		return nil
	}

	return fmt.Errorf("URL ID must be either a SHA-256 hash (64 hex chars) or unpadded base64-encoded URL")
}
