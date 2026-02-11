package mocks

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jarcoal/httpmock"
)

// AttackTacticsMock handles mock responses for attack_tactics service
type AttackTacticsMock struct {
	mockState []string
}

func init() {
	httpmock.RegisterNoResponder(httpmock.NewStringResponder(404, `{"error": {"code": "NotFoundError", "message": "Endpoint not found"}}`))
}

// NewAttackTacticsMock creates a new AttackTacticsMock instance
func NewAttackTacticsMock() *AttackTacticsMock {
	return &AttackTacticsMock{
		mockState: make([]string, 0),
	}
}

// loadMockResponse loads a mock JSON file from the mocks directory
func loadMockResponse(filename string) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	filePath := filepath.Join(dir, "mocks", filename)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read mock file %s: %w", filename, err)
	}

	return string(data), nil
}

// RegisterMocks registers all success mock responses
func (m *AttackTacticsMock) RegisterMocks(baseURL string) {
	m.RegisterGetAttackTacticMock(baseURL)
	m.RegisterGetObjectsRelatedToAttackTacticMock(baseURL)
	m.RegisterGetObjectDescriptorsRelatedToAttackTacticMock(baseURL)
}

// RegisterGetAttackTacticMock registers mock for GET /attack_tactics/{id}
func (m *AttackTacticsMock) RegisterGetAttackTacticMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_attack_tactic.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_tactics/TA0004",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_tactics/TA0004")
}

// RegisterGetObjectsRelatedToAttackTacticMock registers mock for GET /attack_tactics/{id}/{relationship}
func (m *AttackTacticsMock) RegisterGetObjectsRelatedToAttackTacticMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_related_objects.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_tactics/TA0004/attack_techniques",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_tactics/TA0004/attack_techniques")
}

// RegisterGetObjectDescriptorsRelatedToAttackTacticMock registers mock for GET /attack_tactics/{id}/relationships/{relationship}
func (m *AttackTacticsMock) RegisterGetObjectDescriptorsRelatedToAttackTacticMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_object_descriptors.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_tactics/TA0004/relationships/attack_techniques",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_tactics/TA0004/relationships/attack_techniques")
}

// RegisterErrorMocks registers all error mock responses
func (m *AttackTacticsMock) RegisterErrorMocks(baseURL string) {
	m.RegisterUnauthorizedErrorMock(baseURL)
	m.RegisterNotFoundErrorMock(baseURL)
}

// RegisterUnauthorizedErrorMock registers mock for unauthorized error
func (m *AttackTacticsMock) RegisterUnauthorizedErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_unauthorized.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_tactics/invalid-id",
		httpmock.NewStringResponder(401, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_tactics/invalid-id:error")
}

// RegisterNotFoundErrorMock registers mock for not found error
func (m *AttackTacticsMock) RegisterNotFoundErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_not_found.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_tactics/nonexistent-id",
		httpmock.NewStringResponder(404, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_tactics/nonexistent-id:error")
}

// CleanupMockState clears registered mock state
func (m *AttackTacticsMock) CleanupMockState() {
	m.mockState = []string{}
}
