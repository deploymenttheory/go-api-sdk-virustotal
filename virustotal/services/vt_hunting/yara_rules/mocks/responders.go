package mocks

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/jarcoal/httpmock"
)

type YaraRulesMock struct{}

func NewYaraRulesMock() *YaraRulesMock {
	return &YaraRulesMock{}
}

func (m *YaraRulesMock) RegisterMocks() {
	m.RegisterListYaraRulesMock()
	m.RegisterGetYaraRuleMock()
	m.RegisterGetRelatedObjectsMock()
	m.RegisterGetObjectDescriptorsMock()
	m.RegisterCommonErrorMocks()
}

func (m *YaraRulesMock) RegisterListYaraRulesMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/yara_rules",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_list_yara_rules.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

func (m *YaraRulesMock) RegisterGetYaraRuleMock() {
	httpmock.RegisterResponder(
		"GET",
		`=~^https://www\.virustotal\.com/api/v3/yara_rules/[^/]+$`,
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_yara_rule.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

func (m *YaraRulesMock) RegisterGetRelatedObjectsMock() {
	httpmock.RegisterResponder(
		"GET",
		`=~^https://www\.virustotal\.com/api/v3/yara_rules/[^/]+/files$`,
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_related_objects.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

func (m *YaraRulesMock) RegisterGetObjectDescriptorsMock() {
	httpmock.RegisterResponder(
		"GET",
		`=~^https://www\.virustotal\.com/api/v3/yara_rules/[^/]+/relationships/files$`,
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_object_descriptors.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

func (m *YaraRulesMock) RegisterCommonErrorMocks() {
	// 400 Bad Request
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/yara_rules/invalid",
		httpmock.NewStringResponder(400, `{
			"error": {
				"code": "BadRequestError",
				"message": "Invalid YARA rule ID"
			}
		}`),
	)

	// 404 Not Found
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/yara_rules/notfound|test",
		httpmock.NewStringResponder(404, `{
			"error": {
				"code": "NotFoundError",
				"message": "YARA rule not found"
			}
		}`),
	)
}

func (m *YaraRulesMock) loadMockData(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mockDir := filepath.Dir(currentFile)
	mockPath := filepath.Join(mockDir, filename)
	data, err := os.ReadFile(mockPath)
	if err != nil {
		panic("Failed to load mock data from " + mockPath + ": " + err.Error())
	}
	return data
}
