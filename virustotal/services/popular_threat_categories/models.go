package popular_threat_categories

// PopularThreatCategoriesResponse represents the response from GET /popular_threat_categories
type PopularThreatCategoriesResponse struct {
	Data  []ThreatCategory `json:"data"`
	Links Links            `json:"links,omitempty"`
}

// ThreatCategory represents a popular threat category
type ThreatCategory struct {
	Type       string                   `json:"type"`
	ID         string                   `json:"id"`
	Attributes ThreatCategoryAttributes `json:"attributes"`
	Links      *Links                   `json:"links,omitempty"`
}

// ThreatCategoryAttributes contains the attributes of a threat category
type ThreatCategoryAttributes struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Links represents the links section of an object
type Links struct {
	Self string `json:"self"` // URL to this object
}
