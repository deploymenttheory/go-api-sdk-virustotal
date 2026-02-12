package mocks

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jarcoal/httpmock"
)

// AttackTechniquesMock handles mock responses for attack_techniques service
type AttackTechniquesMock struct {
	mockState []string
}

func init() {
	httpmock.RegisterNoResponder(httpmock.NewStringResponder(404, `{"error": {"code": "NotFoundError", "message": "Endpoint not found"}}`))
}

// NewAttackTechniquesMock creates a new AttackTechniquesMock instance
func NewAttackTechniquesMock() *AttackTechniquesMock {
	return &AttackTechniquesMock{
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
func (m *AttackTechniquesMock) RegisterMocks(baseURL string) {
	m.RegisterGetAttackTechniqueMock(baseURL)
	m.RegisterGetObjectsRelatedToAttackTechniqueMock(baseURL)
	m.RegisterGetObjectDescriptorsRelatedToAttackTechniqueMock(baseURL)
}

// RegisterGetAttackTechniqueMock registers mock for GET /attack_techniques/{id}
func (m *AttackTechniquesMock) RegisterGetAttackTechniqueMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_attack_technique.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_techniques/T1548",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_techniques/T1548")
}

// RegisterGetObjectsRelatedToAttackTechniqueMock registers mock for GET /attack_techniques/{id}/{relationship}
func (m *AttackTechniquesMock) RegisterGetObjectsRelatedToAttackTechniqueMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_related_objects.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_techniques/T1548/attack_tactics",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_techniques/T1548/attack_tactics")
}

// RegisterGetObjectDescriptorsRelatedToAttackTechniqueMock registers mock for GET /attack_techniques/{id}/relationships/{relationship}
func (m *AttackTechniquesMock) RegisterGetObjectDescriptorsRelatedToAttackTechniqueMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_object_descriptors.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_techniques/T1548/relationships/attack_tactics",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_techniques/T1548/relationships/attack_tactics")
}

// RegisterRelationshipMocks registers all relationship endpoint mocks
func (m *AttackTechniquesMock) RegisterRelationshipMocks(baseURL string) {
	baseURLT1548 := baseURL + "/attack_techniques/T1548"
	baseURLT1548001 := baseURL + "/attack_techniques/T1548.001"
	baseURLT1156 := baseURL + "/attack_techniques/T1156"

	relationships := map[string]string{
		baseURLT1548 + "/attack_tactics":       "validate_relationship_attack_tactics.json",
		baseURLT1548 + "/subtechniques":        "validate_relationship_subtechniques.json",
		baseURLT1548 + "/threat_actors":        "validate_relationship_threat_actors.json",
		baseURLT1548001 + "/parent_technique":  "validate_relationship_parent_technique.json",
		baseURLT1156 + "/revoking_technique":   "validate_relationship_revoking_technique.json",
	}

	for endpoint, mockFile := range relationships {
		ep := endpoint
		file := mockFile

		httpmock.RegisterResponder(
			"GET",
			ep,
			func(req *http.Request) (*http.Response, error) {
				mockData, err := loadMockResponse(file)
				if err != nil {
					return nil, err
				}
				resp := httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
					"Content-Type": []string{"application/json"},
				})
				return resp(req)
			},
		)
	}
}

// RegisterErrorMocks registers all error mock responses
func (m *AttackTechniquesMock) RegisterErrorMocks(baseURL string) {
	m.RegisterUnauthorizedErrorMock(baseURL)
	m.RegisterNotFoundErrorMock(baseURL)
}

// RegisterUnauthorizedErrorMock registers mock for unauthorized error
func (m *AttackTechniquesMock) RegisterUnauthorizedErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_unauthorized.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_techniques/invalid-id",
		httpmock.NewStringResponder(401, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_techniques/invalid-id:error")
}

// RegisterNotFoundErrorMock registers mock for not found error
func (m *AttackTechniquesMock) RegisterNotFoundErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_not_found.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/attack_techniques/nonexistent-id",
		httpmock.NewStringResponder(404, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/attack_techniques/nonexistent-id:error")
}

// CleanupMockState clears registered mock state
func (m *AttackTechniquesMock) CleanupMockState() {
	m.mockState = []string{}
}
