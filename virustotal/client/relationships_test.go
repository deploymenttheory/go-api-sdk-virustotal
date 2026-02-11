package client

import (
	"testing"
)

func TestRelationshipBuilder_BuildEndpoint(t *testing.T) {
	tests := []struct {
		name          string
		baseEndpoint  string
		id            string
		relationships []string
		endpointType  RelationshipEndpointType
		asQuery       bool
		want          string
		wantErr       bool
	}{
		{
			name:          "full objects endpoint - single relationship",
			baseEndpoint:  "/files",
			id:            "abc123",
			relationships: []string{"comments"},
			endpointType:  RelationshipTypeFull,
			asQuery:       false,
			want:          "/files/abc123/comments",
			wantErr:       false,
		},
		{
			name:          "descriptor endpoint - single relationship",
			baseEndpoint:  "/files",
			id:            "abc123",
			relationships: []string{"comments"},
			endpointType:  RelationshipTypeDescriptor,
			asQuery:       false,
			want:          "/files/abc123/relationships/comments",
			wantErr:       false,
		},
		{
			name:          "query parameter mode - multiple relationships",
			baseEndpoint:  "/domains",
			id:            "example.com",
			relationships: []string{"comments", "votes", "analyses"},
			asQuery:       true,
			want:          "/domains/example.com",
			wantErr:       false,
		},
		{
			name:          "query parameter mode - single relationship",
			baseEndpoint:  "/urls",
			id:            "url123",
			relationships: []string{"comments"},
			asQuery:       true,
			want:          "/urls/url123",
			wantErr:       false,
		},
		{
			name:          "error - empty base endpoint",
			baseEndpoint:  "",
			id:            "abc123",
			relationships: []string{"comments"},
			want:          "",
			wantErr:       true,
		},
		{
			name:          "error - empty id",
			baseEndpoint:  "/files",
			id:            "",
			relationships: []string{"comments"},
			want:          "",
			wantErr:       true,
		},
		{
			name:          "error - no relationships in endpoint mode",
			baseEndpoint:  "/files",
			id:            "abc123",
			relationships: []string{},
			asQuery:       false,
			want:          "",
			wantErr:       true,
		},
		{
			name:          "error - multiple relationships in endpoint mode",
			baseEndpoint:  "/files",
			id:            "abc123",
			relationships: []string{"comments", "votes"},
			asQuery:       false,
			want:          "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewRelationshipBuilder(tt.baseEndpoint, tt.id)

			for _, rel := range tt.relationships {
				rb.WithRelationship(rel)
			}

			if tt.endpointType == RelationshipTypeDescriptor {
				rb.AsDescriptorsOnly()
			}

			if tt.asQuery {
				rb.AsQueryParameter()
			}

			got, err := rb.BuildEndpoint()
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BuildEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRelationshipBuilder_BuildQueryParams(t *testing.T) {
	tests := []struct {
		name          string
		relationships []string
		asQuery       bool
		want          string
		wantEmpty     bool
	}{
		{
			name:          "query parameter mode - multiple relationships",
			relationships: []string{"comments", "votes", "analyses"},
			asQuery:       true,
			want:          "comments,votes,analyses",
			wantEmpty:     false,
		},
		{
			name:          "query parameter mode - single relationship",
			relationships: []string{"comments"},
			asQuery:       true,
			want:          "comments",
			wantEmpty:     false,
		},
		{
			name:          "endpoint mode - should return empty",
			relationships: []string{"comments"},
			asQuery:       false,
			want:          "",
			wantEmpty:     true,
		},
		{
			name:          "no relationships - should return empty",
			relationships: []string{},
			asQuery:       true,
			want:          "",
			wantEmpty:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewRelationshipBuilder("files", "abc123")

			for _, rel := range tt.relationships {
				rb.WithRelationship(rel)
			}

			if tt.asQuery {
				rb.AsQueryParameter()
			}

			params := rb.BuildQueryParams()

			if tt.wantEmpty {
				if len(params) != 0 {
					t.Errorf("BuildQueryParams() expected empty map, got %v", params)
				}
			} else {
				if val, ok := params["relationships"]; !ok {
					t.Errorf("BuildQueryParams() missing 'relationships' key")
				} else if val != tt.want {
					t.Errorf("BuildQueryParams() = %v, want %v", val, tt.want)
				}
			}
		})
	}
}

func TestRelationshipBuilder_WithRelationships(t *testing.T) {
	rb := NewRelationshipBuilder("/files", "abc123")
	rb.WithRelationships("comments", "votes", "analyses")

	if len(rb.relationships) != 3 {
		t.Errorf("WithRelationships() expected 3 relationships, got %d", len(rb.relationships))
	}

	expected := []string{"comments", "votes", "analyses"}
	for i, rel := range rb.relationships {
		if rel != expected[i] {
			t.Errorf("WithRelationships() relationship[%d] = %v, want %v", i, rel, expected[i])
		}
	}
}

func TestRelationshipBuilder_Build(t *testing.T) {
	tests := []struct {
		name             string
		baseEndpoint     string
		id               string
		relationships    []string
		descriptorsOnly  bool
		asQuery          bool
		wantEndpoint     string
		wantQueryParam   string
		wantErr          bool
	}{
		{
			name:            "full objects with query params",
			baseEndpoint:    "/files",
			id:              "abc123",
			relationships:   []string{"comments", "votes"},
			asQuery:         true,
			wantEndpoint:    "/files/abc123",
			wantQueryParam:  "comments,votes",
			wantErr:         false,
		},
		{
			name:            "descriptors only endpoint",
			baseEndpoint:    "/domains",
			id:              "example.com",
			relationships:   []string{"resolutions"},
			descriptorsOnly: true,
			asQuery:         false,
			wantEndpoint:    "/domains/example.com/relationships/resolutions",
			wantQueryParam:  "",
			wantErr:         false,
		},
		{
			name:            "full objects endpoint",
			baseEndpoint:    "/urls",
			id:              "url123",
			relationships:   []string{"comments"},
			descriptorsOnly: false,
			asQuery:         false,
			wantEndpoint:    "/urls/url123/comments",
			wantQueryParam:  "",
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewRelationshipBuilder(tt.baseEndpoint, tt.id)
			rb.WithRelationships(tt.relationships...)

			if tt.descriptorsOnly {
				rb.AsDescriptorsOnly()
			}

			if tt.asQuery {
				rb.AsQueryParameter()
			}

			endpoint, queryParams, err := rb.Build()
			if (err != nil) != tt.wantErr {
				t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if endpoint != tt.wantEndpoint {
				t.Errorf("Build() endpoint = %v, want %v", endpoint, tt.wantEndpoint)
			}

			if tt.wantQueryParam != "" {
				if val, ok := queryParams["relationships"]; !ok {
					t.Errorf("Build() missing 'relationships' query param")
				} else if val != tt.wantQueryParam {
					t.Errorf("Build() query param = %v, want %v", val, tt.wantQueryParam)
				}
			} else {
				if len(queryParams) != 0 {
					t.Errorf("Build() expected empty query params, got %v", queryParams)
				}
			}
		})
	}
}

func TestBuildRelationshipEndpoint(t *testing.T) {
	tests := []struct {
		name            string
		baseEndpoint    string
		id              string
		relationship    string
		descriptorsOnly bool
		want            string
		wantErr         bool
	}{
		{
			name:            "full objects endpoint",
			baseEndpoint:    "/files",
			id:              "abc123",
			relationship:    "comments",
			descriptorsOnly: false,
			want:            "/files/abc123/comments",
			wantErr:         false,
		},
		{
			name:            "descriptors only endpoint",
			baseEndpoint:    "/files",
			id:              "abc123",
			relationship:    "comments",
			descriptorsOnly: true,
			want:            "/files/abc123/relationships/comments",
			wantErr:         false,
		},
		{
			name:            "domains with resolutions",
			baseEndpoint:    "/domains",
			id:              "example.com",
			relationship:    "resolutions",
			descriptorsOnly: false,
			want:            "/domains/example.com/resolutions",
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildRelationshipEndpoint(tt.baseEndpoint, tt.id, tt.relationship, tt.descriptorsOnly)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildRelationshipEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BuildRelationshipEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildRelationshipQueryParam(t *testing.T) {
	tests := []struct {
		name          string
		relationships []string
		want          string
	}{
		{
			name:          "single relationship",
			relationships: []string{"comments"},
			want:          "comments",
		},
		{
			name:          "multiple relationships",
			relationships: []string{"comments", "votes", "analyses"},
			want:          "comments,votes,analyses",
		},
		{
			name:          "empty relationships",
			relationships: []string{},
			want:          "",
		},
		{
			name:          "with empty strings filtered",
			relationships: []string{"comments", "", "votes"},
			want:          "comments,votes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildRelationshipQueryParam(tt.relationships...)
			if got != tt.want {
				t.Errorf("BuildRelationshipQueryParam() = %v, want %v", got, tt.want)
			}
		})
	}
}
