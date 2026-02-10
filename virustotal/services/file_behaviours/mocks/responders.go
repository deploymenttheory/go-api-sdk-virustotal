package mocks

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jarcoal/httpmock"
)

// FileBehavioursMock handles mock responses for file behaviours service
type FileBehavioursMock struct {
	mockState []string
}

func init() {
	httpmock.RegisterNoResponder(httpmock.NewStringResponder(404, `{"error": {"code": "NotFoundError", "message": "Endpoint not found"}}`))
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
func (m *FileBehavioursMock) RegisterMocks(baseURL string) {
	m.RegisterGetFileBehaviourSummaryMock(baseURL)
	m.RegisterGetAllFileBehavioursSummaryMock(baseURL)
	m.RegisterGetFileMitreAttackTreesMock(baseURL)
	m.RegisterGetAllFileBehavioursMock(baseURL)
	m.RegisterGetFileBehaviourMock(baseURL)
	m.RegisterGetObjectsRelatedToFileBehaviourMock(baseURL)
	m.RegisterGetObjectDescriptorsForFileBehaviourMock(baseURL)
	m.RegisterGetFileBehaviourHTMLMock(baseURL)
	m.RegisterGetFileBehaviourEVTXMock(baseURL)
	m.RegisterGetFileBehaviourPCAPMock(baseURL)
	m.RegisterGetFileBehaviourMemdumpMock(baseURL)
}

// RegisterGetFileBehaviourSummaryMock registers mock for GET /files/{id}/behaviour_summary
func (m *FileBehavioursMock) RegisterGetFileBehaviourSummaryMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_behaviour_summary.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	// Register for MD5 hash
	httpmock.RegisterResponder(
		"GET",
		baseURL+"/files/44d88612fea8a8f36de82e1278abb02f/behaviour_summary",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/files/44d88612fea8a8f36de82e1278abb02f/behaviour_summary")
}

// RegisterGetAllFileBehavioursSummaryMock registers mock for GET /files/behaviour_summary
func (m *FileBehavioursMock) RegisterGetAllFileBehavioursSummaryMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_all_behaviours_summary.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/files/behaviour_summary",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/files/behaviour_summary")
}

// RegisterGetFileMitreAttackTreesMock registers mock for GET /files/{id}/behaviour_mitre_trees
func (m *FileBehavioursMock) RegisterGetFileMitreAttackTreesMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_mitre_trees.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	// Register for SHA-256 hash
	httpmock.RegisterResponder(
		"GET",
		baseURL+"/files/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08/behaviour_mitre_trees",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/files/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08/behaviour_mitre_trees")
}

// RegisterGetAllFileBehavioursMock registers mock for GET /files/{id}/behaviours
func (m *FileBehavioursMock) RegisterGetAllFileBehavioursMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_all_behaviours.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	// Register for SHA-1 hash
	httpmock.RegisterResponder(
		"GET",
		baseURL+"/files/356a192b7913b04c54574d18c28d46e6395428ab/behaviours",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/files/356a192b7913b04c54574d18c28d46e6395428ab/behaviours")
}

// RegisterGetFileBehaviourMock registers mock for GET /file_behaviours/{sandbox_id}
func (m *FileBehavioursMock) RegisterGetFileBehaviourMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_behaviour.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/file_behaviours/sandbox123",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/file_behaviours/sandbox123")
}

// RegisterGetObjectsRelatedToFileBehaviourMock registers mock for GET /file_behaviours/{sandbox_id}/{relationship}
func (m *FileBehavioursMock) RegisterGetObjectsRelatedToFileBehaviourMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_related_objects.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/file_behaviours/sandbox123/attack_techniques",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/file_behaviours/sandbox123/attack_techniques")
}

// RegisterGetObjectDescriptorsForFileBehaviourMock registers mock for GET /file_behaviours/{sandbox_id}/relationships/{relationship}
func (m *FileBehavioursMock) RegisterGetObjectDescriptorsForFileBehaviourMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_object_descriptors.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/file_behaviours/sandbox123/relationships/attack_techniques",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/file_behaviours/sandbox123/relationships/attack_techniques")
}

// RegisterGetFileBehaviourHTMLMock registers mock for GET /file_behaviours/{sandbox_id}/html
func (m *FileBehavioursMock) RegisterGetFileBehaviourHTMLMock(baseURL string) {
	mockData := `<!DOCTYPE html><html><head><title>Behaviour Report</title></head><body><h1>Test Behaviour Report</h1></body></html>`

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/file_behaviours/sandbox123/html",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"text/html"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/file_behaviours/sandbox123/html")
}

// RegisterGetFileBehaviourEVTXMock registers mock for GET /file_behaviours/{sandbox_id}/evtx
func (m *FileBehavioursMock) RegisterGetFileBehaviourEVTXMock(baseURL string) {
	mockData := []byte{0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00} // Mock binary data

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/file_behaviours/sandbox123/evtx",
		httpmock.NewBytesResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/octet-stream"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/file_behaviours/sandbox123/evtx")
}

// RegisterGetFileBehaviourPCAPMock registers mock for GET /file_behaviours/{sandbox_id}/pcap
func (m *FileBehavioursMock) RegisterGetFileBehaviourPCAPMock(baseURL string) {
	mockData := []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00} // Mock PCAP header

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/file_behaviours/sandbox123/pcap",
		httpmock.NewBytesResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/vnd.tcpdump.pcap"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/file_behaviours/sandbox123/pcap")
}

// RegisterGetFileBehaviourMemdumpMock registers mock for GET /file_behaviours/{sandbox_id}/memdump
func (m *FileBehavioursMock) RegisterGetFileBehaviourMemdumpMock(baseURL string) {
	mockData := []byte{0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00} // Mock PE header

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/file_behaviours/sandbox123/memdump",
		httpmock.NewBytesResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/octet-stream"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/file_behaviours/sandbox123/memdump")
}

// RegisterErrorMocks registers all error mock responses
func (m *FileBehavioursMock) RegisterErrorMocks(baseURL string) {
	m.RegisterUnauthorizedErrorMock(baseURL)
	m.RegisterNotFoundErrorMock(baseURL)
}

// RegisterUnauthorizedErrorMock registers mock for unauthorized error
func (m *FileBehavioursMock) RegisterUnauthorizedErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_unauthorized.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	// Use valid MD5 hash for error mock
	httpmock.RegisterResponder(
		"GET",
		baseURL+"/files/44d88612fea8a8f36de82e1278abb02f/behaviour_summary",
		httpmock.NewStringResponder(401, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/files/44d88612fea8a8f36de82e1278abb02f/behaviour_summary:error")
}

// RegisterNotFoundErrorMock registers mock for not found error
func (m *FileBehavioursMock) RegisterNotFoundErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_not_found.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	// Use valid SHA-256 hash for not found error mock
	httpmock.RegisterResponder(
		"GET",
		baseURL+"/files/0000000000000000000000000000000000000000000000000000000000000000/behaviour_summary",
		httpmock.NewStringResponder(404, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/files/0000000000000000000000000000000000000000000000000000000000000000/behaviour_summary:error")
}

// CleanupMockState clears registered mock state
func (m *FileBehavioursMock) CleanupMockState() {
	m.mockState = []string{}
}
