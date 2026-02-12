package code_insights

// HistoryResponse represents a previous analysis response in the history
type HistoryResponse struct {
	Summary     string `json:"summary"`
	Description string `json:"description"`
}

// HistoryEntry represents a single entry in the analysis history
type HistoryEntry struct {
	Request  string          `json:"request"`
	Response HistoryResponse `json:"response"`
}

// AnalyseCodeData represents the data payload for code analysis request
type AnalyseCodeData struct {
	Code     string         `json:"code"`
	CodeType string         `json:"code_type"`
	History  []HistoryEntry `json:"history,omitempty"`
}

// =============================================================================
// Analyse Code Request
// =============================================================================

// AnalyseCodeRequest represents the request body for analyzing code
type AnalyseCodeRequest struct {
	Data AnalyseCodeData `json:"data"`
}

// =============================================================================
// Analyse Code Response
// =============================================================================

// AnalyseCodeResponse represents the response from code analysis
//
// The response data field contains a base64-encoded description of the code's functionality
type AnalyseCodeResponse struct {
	Data string `json:"data"`
}
