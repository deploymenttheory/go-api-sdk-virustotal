package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
	"go.uber.org/zap"
	"resty.dev/v3"
)

// toInterfaceResponse converts a resty.Response to interfaces.Response
func toInterfaceResponse(resp *resty.Response) *interfaces.Response {
	if resp == nil {
		return &interfaces.Response{
			Headers: make(http.Header),
		}
	}
	
	return &interfaces.Response{
		StatusCode: resp.StatusCode(),
		Status:     resp.Status(),
		Headers:    resp.Header(),
		Body:       []byte(resp.String()),
	}
}

// Get executes a GET request
func (c *Client) Get(ctx context.Context, path string, queryParams map[string]string, headers map[string]string, result any) (*interfaces.Response, error) {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	for k, v := range queryParams {
		if v != "" {
			req.SetQueryParam(k, v)
		}
	}

	c.applyHeaders(req, headers)

	return c.executeRequest(req, "GET", path)
}

// Post executes a POST request with JSON body
func (c *Client) Post(ctx context.Context, path string, body any, headers map[string]string, result any) (*interfaces.Response, error) {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if body != nil {
		req.SetBody(body)
	}

	c.applyHeaders(req, headers)

	return c.executeRequest(req, "POST", path)
}

// PostWithQuery executes a POST request with both body and query parameters
func (c *Client) PostWithQuery(ctx context.Context, path string, queryParams map[string]string, body any, headers map[string]string, result any) (*interfaces.Response, error) {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	for k, v := range queryParams {
		if v != "" {
			req.SetQueryParam(k, v)
		}
	}

	if body != nil {
		req.SetBody(body)
	}

	c.applyHeaders(req, headers)

	return c.executeRequest(req, "POST", path)
}

// PostForm executes a POST request with form-urlencoded data
func (c *Client) PostForm(ctx context.Context, path string, formData map[string]string, headers map[string]string, result any) (*interfaces.Response, error) {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if formData != nil {
		req.SetFormData(formData)
	}

	// Apply headers with precedence (global first, then per-request)
	// Note: Content-Type is handled automatically by resty for form data
	for k, v := range c.globalHeaders {
		if v != "" && k != "Content-Type" {
			req.SetHeader(k, v)
		}
	}
	for k, v := range headers {
		if v != "" && k != "Content-Type" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "POST", path)
}

// PostMultipart executes a POST request with multipart form data and progress tracking
func (c *Client) PostMultipart(ctx context.Context, path string, fileField string, fileName string, fileReader io.Reader, fileSize int64, formFields map[string]string, headers map[string]string, progressCallback interfaces.MultipartProgressCallback, result any) (*interfaces.Response, error) {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	// Set file field using SetMultipartFields with progress callback
	if fileReader != nil && fileName != "" && fileField != "" {
		multipartField := &resty.MultipartField{
			Name:     fileField,
			FileName: fileName,
			Reader:   fileReader,
			FileSize: fileSize,
		}

		// Add progress callback if provided
		if progressCallback != nil {
			multipartField.ProgressCallback = func(progress resty.MultipartFieldProgress) {
				progressCallback(progress.Name, progress.FileName, progress.Written, progress.FileSize)
			}
		}

		req.SetMultipartFields(multipartField)
	}

	// Set form fields using SetMultipartFormData for multipart requests
	if len(formFields) > 0 {
		req.SetMultipartFormData(formFields)
	}

	// Apply headers with precedence (global first, then per-request)
	// Note: Content-Type is handled automatically by resty for multipart
	for k, v := range c.globalHeaders {
		if v != "" && k != "Content-Type" {
			req.SetHeader(k, v)
		}
	}
	for k, v := range headers {
		if v != "" && k != "Content-Type" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "POST", path)
}

// Put executes a PUT request
func (c *Client) Put(ctx context.Context, path string, body any, headers map[string]string, result any) (*interfaces.Response, error) {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if body != nil {
		req.SetBody(body)
	}

	c.applyHeaders(req, headers)

	return c.executeRequest(req, "PUT", path)
}

// Patch executes a PATCH request
func (c *Client) Patch(ctx context.Context, path string, body any, headers map[string]string, result any) (*interfaces.Response, error) {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if body != nil {
		req.SetBody(body)
	}

	c.applyHeaders(req, headers)

	return c.executeRequest(req, "PATCH", path)
}

// Delete executes a DELETE request
func (c *Client) Delete(ctx context.Context, path string, queryParams map[string]string, headers map[string]string, result any) (*interfaces.Response, error) {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	for k, v := range queryParams {
		if v != "" {
			req.SetQueryParam(k, v)
		}
	}

	c.applyHeaders(req, headers)

	return c.executeRequest(req, "DELETE", path)
}

// DeleteWithBody executes a DELETE request with body (for bulk operations)
func (c *Client) DeleteWithBody(ctx context.Context, path string, body any, headers map[string]string, result any) (*interfaces.Response, error) {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if body != nil {
		req.SetBody(body)
	}

	c.applyHeaders(req, headers)

	return c.executeRequest(req, "DELETE", path)
}

// GetBytes performs a GET request and returns raw bytes without unmarshaling
// Use this for non-JSON responses like HTML, CSV, binary files (EVTX, PCAP, memdump), etc.
// Apply headers with precedence (global first, then per-request)
func (c *Client) GetBytes(ctx context.Context, path string, queryParams map[string]string, headers map[string]string) (*interfaces.Response, []byte, error) {
	req := c.client.R().
		SetContext(ctx)

	for k, v := range queryParams {
		if v != "" {
			req.SetQueryParam(k, v)
		}
	}

	c.applyHeaders(req, headers)

	c.logger.Debug("Executing bytes request",
		zap.String("method", "GET"),
		zap.String("path", path))

	resp, err := req.Get(path)
	ifaceResp := toInterfaceResponse(resp)
	if err != nil {
		c.logger.Error("Bytes request failed",
			zap.String("path", path),
			zap.Error(err))
		return ifaceResp, nil, fmt.Errorf("bytes request failed: %w", err)
	}

	if resp.IsError() {
		return ifaceResp, nil, ParseErrorResponse(
			[]byte(resp.String()),
			resp.StatusCode(),
			resp.Status(),
			"GET",
			path,
			c.logger,
		)
	}

	body := []byte(resp.String())
	c.logger.Debug("Bytes request completed successfully",
		zap.String("path", path),
		zap.Int("status_code", resp.StatusCode()),
		zap.Int("content_length", len(body)))

	return ifaceResp, body, nil
}

// executeRequest is a centralized request executor that handles error processing
// Returns response metadata and error. Response is always non-nil for accessing headers.
func (c *Client) executeRequest(req *resty.Request, method, path string) (*interfaces.Response, error) {
	c.logger.Debug("Executing API request",
		zap.String("method", method),
		zap.String("path", path))

	var resp *resty.Response
	var err error

	switch method {
	case "GET":
		resp, err = req.Get(path)
	case "POST":
		resp, err = req.Post(path)
	case "PUT":
		resp, err = req.Put(path)
	case "PATCH":
		resp, err = req.Patch(path)
	case "DELETE":
		resp, err = req.Delete(path)
	default:
		return toInterfaceResponse(nil), fmt.Errorf("unsupported HTTP method: %s", method)
	}

	// Convert to interface response (always return response metadata)
	ifaceResp := toInterfaceResponse(resp)

	if err != nil {
		c.logger.Error("Request failed",
			zap.String("method", method),
			zap.String("path", path),
			zap.Error(err))
		return ifaceResp, fmt.Errorf("request failed: %w", err)
	}

	// Validate response before processing
	if err := c.validateResponse(resp, method, path); err != nil {
		return ifaceResp, err
	}

	if resp.IsError() {
		return ifaceResp, ParseErrorResponse(
			[]byte(resp.String()),
			resp.StatusCode(),
			resp.Status(),
			method,
			path,
			c.logger,
		)
	}

	c.logger.Debug("Request completed successfully",
		zap.String("method", method),
		zap.String("path", path),
		zap.Int("status_code", resp.StatusCode()))

	return ifaceResp, nil
}

// validateResponse validates the HTTP response before processing
// This includes checking for empty responses and validating Content-Type for JSON endpoints
func (c *Client) validateResponse(resp *resty.Response, method, path string) error {
	// Handle empty responses (204 No Content, etc.)
	bodyLen := len(resp.String())
	if resp.Header().Get("Content-Length") == "0" || bodyLen == 0 {
		c.logger.Debug("Empty response received",
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status_code", resp.StatusCode()))
		return nil
	}

	// For non-error responses with content, validate Content-Type is JSON
	// Skip validation for:
	// - Error responses (handled by error parser)
	// - Endpoints that explicitly return non-JSON (download endpoints, etc.)
	if !resp.IsError() && bodyLen > 0 {
		contentType := resp.Header().Get("Content-Type")

		// Allow responses without Content-Type header (some endpoints don't set it)
		if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
			c.logger.Warn("Unexpected Content-Type in response",
				zap.String("method", method),
				zap.String("path", path),
				zap.String("content_type", contentType),
				zap.String("expected", "application/json"))

			return fmt.Errorf("unexpected response Content-Type from %s %s: got %q, expected application/json",
				method, path, contentType)
		}
	}

	return nil
}
