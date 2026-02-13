package code_insights

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// CodeInsightsServiceInterface defines the interface for code insights operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/analyse-binary
	CodeInsightsServiceInterface interface {
		// AnalyseCode analyses disassembled or decompiled code
		//
		// Analyzes disassembled or decompiled code and returns a Base64-encoded description
		// of the functionality, focusing on aspects relevant to malware analysis.
		// The input code must be Base64-encoded.
		//
		// Note: This endpoint is limited to 50 requests per day.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/analyse-binary
		AnalyseCode(ctx context.Context, code string, codeType string, history []HistoryEntry) (*AnalyseCodeResponse, *interfaces.Response, error)
	}

	// Service implements the CodeInsightsServiceInterface
	Service struct {
		client interfaces.HTTPClient
	}
)

var _ CodeInsightsServiceInterface = (*Service)(nil)

func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// =============================================================================
// Analyse Code Operations
// =============================================================================

// AnalyseCode analyses disassembled or decompiled code
// URL: POST https://www.virustotal.com/api/v3/codeinsights/analyse-binary
// https://docs.virustotal.com/reference/analyse-binary
func (s *Service) AnalyseCode(ctx context.Context, code string, codeType string, history []HistoryEntry) (*AnalyseCodeResponse, *interfaces.Response, error) {
	if err := ValidateBase64(code); err != nil {
		return nil, client.NewEmptyResponse(), fmt.Errorf("code validation failed: %w", err)
	}

	if err := ValidateCodeType(codeType); err != nil {
		return nil, client.NewEmptyResponse(), fmt.Errorf("code type validation failed: %w", err)
	}

	for i, entry := range history {
		if err := ValidateBase64(entry.Request); err != nil {
			return nil, client.NewEmptyResponse(), fmt.Errorf("history entry %d request validation failed: %w", i, err)
		}
	}

	endpoint := EndpointCodeInsights

	requestBody := AnalyseCodeRequest{
		Data: AnalyseCodeData{
			Code:     code,
			CodeType: codeType,
			History:  history,
		},
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result AnalyseCodeResponse
	resp, err := s.client.Post(ctx, endpoint, requestBody, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
