# VirusTotal API Client Specification

## API Characteristics & Design Implications

### Authentication
- **Pattern**: Static API key in HTTP header
- **Header**: `x-apikey: {API_KEY}`
- **Token Lifetime**: No expiration
- **Token Refresh**: Not required
- **Impact on Client**:
  - Simple authentication: API key set once during client initialization
  - No `TokenManager` needed
  - No token refresh logic or middleware
  - Thread-safe by nature (read-only static value)
  - Contrast with Nexthink: No OAuth2 flow, no separate auth endpoint

### API Versioning
- **Pattern**: Version in URL path
- **URL Structure**: `https://www.virustotal.com/api/v3/{resource}`
- **Current Version**: `v3`
- **Impact on Client**:
  - API version embedded in each endpoint path
  - Base URL is `https://www.virustotal.com/api`
  - Each service endpoint includes version prefix (e.g., `/v3/files`, `/v3/search`)
  - No version negotiation via headers
  - Version constant defined in `client/constants.go` as `DefaultAPIVersion = "v3"`
  - Future version changes require updating all endpoint constants
  - Contrast with Workbrew: Workbrew uses `X-Workbrew-API-Version` header instead of URL path

### Pagination
- **Pattern**: Cursor-based pagination
- **Parameters**:
  - `limit`: Number of objects per page (max varies by endpoint)
  - `cursor`: Opaque cursor string from previous response
  
- **Response Structure**:
  ```json
  {
    "data": [...],
    "meta": {
      "cursor": "...",
      "count": N
    },
    "links": {
      "self": "...",
      "next": "..."
    }
  }
  ```
  
- **Impact on Client**:
  - Pagination helpers needed (`SearchOptions`, `GetRelatedObjectsOptions`)
  - Cursor returned in response metadata
  - Client can iterate pages using cursor
  - Contrast with Nexthink: Nexthink has no pagination, uses bulk export for large datasets

### Resource Model
- **Pattern**: RESTful resources with hierarchical relationships
- **Resources**: Files, URLs, Domains, IP Addresses, Comments, Analyses, Collections
- **Relationships**: Each resource has typed relationships to other resources
  - Example: File → contacted_domains, contacted_ips, dropped_files
  
- **Impact on Client**:
  - Standard CRUD operations per resource
  - Relationship navigation via `/files/{id}/{relationship}` pattern
  - Two modes: full objects vs descriptors (IDs only)
  - Contrast with Nexthink: Nexthink uses pre-configured queries, not resource navigation

### File Upload Routing
- **Size-Based Routing**:
  - Files ≤ 32MB: Direct upload to `/files`
  - Files > 32MB and ≤ 650MB: Upload via `/files/upload_url` (get signed URL first)
  - Files > 650MB: Rejected
  
- **Impact on Client**:
  - Client must detect file size before upload
  - Automatic routing logic in `UploadFile()` method
  - Streaming upload to avoid loading entire file into memory
  - Progress callback support for large files
  - Contrast with Nexthink: Nexthink doesn't handle file uploads

### Search Capabilities
- **Basic Search**: Simple query for hash/URL/domain/IP
- **Intelligence Search**: Advanced corpus search with modifiers
  - Syntax: `type:peexe size:90kb+ positives:5+ ls:2024-01-01+`
  - Modifiers: file type, size, detection count, submission date, etc.
  - Content searches (YARA patterns, hex strings)
  
- **Impact on Client**:
  - Two separate search methods (`Search`, `IntelligenceSearch`)
  - Query validation (non-empty strings)
  - Options struct for search parameters (limit, cursor, order, descriptors_only)
  - Content snippet retrieval for matched content
  - Contrast with Nexthink: Nexthink uses pre-configured NQL queries by ID

### Quota & Privilege Tiers
- **Tiers**: Public API, Private/Premium API, VT Intelligence
- **Features Gated**:
  - Intelligence Search: Requires Premium
  - File Download: Requires Premium
  - Metadata endpoint: Requires Premium
  - Fuzzy hash searches: Throttled to ~15/minute
  
- **Impact on Client**:
  - Documentation clearly marks premium-only operations
  - Error responses distinguish permission vs authentication issues
  - No client-side feature gating (API enforces)

### Response Format
- **Standard**: JSON only
- **Content-Type**: `application/json`
- **Structure**: Consistent envelope with `data`, `meta`, `links`
- **Impact on Client**:
  - Single response parsing path
  - No CSV support (unlike Nexthink)
  - Type-safe response structs

### Rate Limiting
- **Pattern**: Standard HTTP 429 with headers
- **Headers**: `Retry-After`, custom rate limit headers (varies)
- **Impact on Client**:
  - Automatic retry with exponential backoff
  - Response wrapper exposes headers
  - Respect `Retry-After` for polite backoff

### Async Operations
- **Pattern**: Submit analysis → poll status → get report
- **Endpoints**:
  - POST `/files` → returns `analysis_id`
  - GET `/analyses/{id}` → returns status and results
  
- **Status Values**: `queued`, `in-progress`, `completed`
- **Impact on Client**:
  - Two-step process: submit + poll
  - No built-in polling helper (client can poll manually)
  - Contrast with Nexthink: Nexthink export is 3-step with external S3 download

### URL Encoding
- **Requirements**: URL and domain parameters must be base64url-encoded (no padding)
- **Example**: `example.com` → `ZXhhbXBsZS5jb20`
- **Impact on Client**:
  - Helper functions for URL encoding/decoding
  - Automatic encoding in URL/domain methods
  - Clear documentation on encoding requirements

### Object Identification
- **Multiple IDs**: Many resources accept multiple ID types
  - Files: MD5, SHA1, SHA256
  - URLs/Domains: Base64url-encoded or raw
  
- **Impact on Client**:
  - Flexible ID acceptance in methods
  - Validation ensures at least one ID provided
  - Helper for ID format conversion

### Error Handling
- **Structured Errors**: JSON error responses
- **Status Codes**:
  - 400: Invalid parameters
  - 401: Invalid API key
  - 403: Permission denied (quota/premium required)
  - 404: Resource not found
  - 429: Rate limit exceeded
  - 503: Service temporarily unavailable
  
- **Impact on Client**:
  - Custom error types
  - Error details extracted from response JSON
  - Response object returned even on error for header access

### Base URL
- **Pattern**: `https://www.virustotal.com/api/v3`
- **Fixed**: No dynamic construction (unlike Nexthink's instance/region pattern)
- **Impact on Client**:
  - Simple constant base URL
  - Optional override for testing/proxies
