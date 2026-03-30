package code_insights

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service implements the CodeInsightsServiceInterface
type Service struct {
	client client.Client
}

func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// =============================================================================
// Analyse Code Operations
// =============================================================================

// AnalyseCode analyses disassembled or decompiled code
// URL: POST https://www.virustotal.com/api/v3/codeinsights/analyse-binary
// https://docs.virustotal.com/reference/analyse-binary
func (s *Service) AnalyseCode(ctx context.Context, code string, codeType string, history []HistoryEntry) (*AnalyseCodeResponse, *resty.Response, error) {
	if err := ValidateBase64(code); err != nil {
		return nil, nil, fmt.Errorf("code validation failed: %w", err)
	}

	if err := ValidateCodeType(codeType); err != nil {
		return nil, nil, fmt.Errorf("code type validation failed: %w", err)
	}

	for i, entry := range history {
		if err := ValidateBase64(entry.Request); err != nil {
			return nil, nil, fmt.Errorf("history entry %d request validation failed: %w", i, err)
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

	var result AnalyseCodeResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(requestBody).
		SetResult(&result).
		Post(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
