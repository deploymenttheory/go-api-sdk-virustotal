package client

import (
	"context"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
	"go.uber.org/zap"
	"resty.dev/v3"
)

// Get executes a GET request
func (c *Client) Get(ctx context.Context, path string, queryParams map[string]string, headers map[string]string, result any) error {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	for k, v := range queryParams {
		if v != "" {
			req.SetQueryParam(k, v)
		}
	}

	for k, v := range headers {
		if v != "" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "GET", path)
}

// Post executes a POST request with JSON body
func (c *Client) Post(ctx context.Context, path string, body any, headers map[string]string, result any) error {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if body != nil {
		req.SetBody(body)
	}

	for k, v := range headers {
		if v != "" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "POST", path)
}

// PostWithQuery executes a POST request with both body and query parameters
func (c *Client) PostWithQuery(ctx context.Context, path string, queryParams map[string]string, body any, headers map[string]string, result any) error {
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

	for k, v := range headers {
		if v != "" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "POST", path)
}

// PostForm executes a POST request with form-urlencoded data
func (c *Client) PostForm(ctx context.Context, path string, formData map[string]string, headers map[string]string, result any) error {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if formData != nil {
		req.SetFormData(formData)
	}

	for k, v := range headers {
		if v != "" && k != "Content-Type" { // Skip Content-Type as resty handles it automatically for form data
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "POST", path)
}

// PostMultipart executes a POST request with multipart form data and progress tracking
func (c *Client) PostMultipart(ctx context.Context, path string, fileField string, fileName string, fileReader io.Reader, fileSize int64, formFields map[string]string, headers map[string]string, progressCallback interfaces.MultipartProgressCallback, result any) error {
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

	// Set headers (excluding Content-Type as resty automatically handles it for multipart)
	for k, v := range headers {
		if v != "" && k != "Content-Type" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "POST", path)
}

// Put executes a PUT request
func (c *Client) Put(ctx context.Context, path string, body any, headers map[string]string, result any) error {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if body != nil {
		req.SetBody(body)
	}

	for k, v := range headers {
		if v != "" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "PUT", path)
}

// Patch executes a PATCH request
func (c *Client) Patch(ctx context.Context, path string, body any, headers map[string]string, result any) error {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if body != nil {
		req.SetBody(body)
	}

	for k, v := range headers {
		if v != "" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "PATCH", path)
}

// Delete executes a DELETE request
func (c *Client) Delete(ctx context.Context, path string, queryParams map[string]string, headers map[string]string, result any) error {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	for k, v := range queryParams {
		if v != "" {
			req.SetQueryParam(k, v)
		}
	}

	for k, v := range headers {
		if v != "" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "DELETE", path)
}

// DeleteWithBody executes a DELETE request with body (for bulk operations)
func (c *Client) DeleteWithBody(ctx context.Context, path string, body any, headers map[string]string, result any) error {
	req := c.client.R().
		SetContext(ctx).
		SetResult(result)

	if body != nil {
		req.SetBody(body)
	}

	for k, v := range headers {
		if v != "" {
			req.SetHeader(k, v)
		}
	}

	return c.executeRequest(req, "DELETE", path)
}

// GetBytes performs a GET request and returns raw bytes without unmarshaling
// Use this for non-JSON responses like HTML, CSV, binary files (EVTX, PCAP, memdump), etc.
func (c *Client) GetBytes(ctx context.Context, path string, queryParams map[string]string, headers map[string]string) ([]byte, error) {
	req := c.client.R().
		SetContext(ctx)

	for k, v := range queryParams {
		if v != "" {
			req.SetQueryParam(k, v)
		}
	}

	for k, v := range headers {
		if v != "" {
			req.SetHeader(k, v)
		}
	}

	c.logger.Debug("Executing bytes request",
		zap.String("method", "GET"),
		zap.String("path", path))

	resp, err := req.Get(path)
	if err != nil {
		c.logger.Error("Bytes request failed",
			zap.String("path", path),
			zap.Error(err))
		return nil, fmt.Errorf("bytes request failed: %w", err)
	}

	if resp.IsError() {
		return nil, ParseErrorResponse(
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

	return body, nil
}

// executeRequest is a centralized request executor that handles error processing
func (c *Client) executeRequest(req *resty.Request, method, path string) error {
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
		return fmt.Errorf("unsupported HTTP method: %s", method)
	}

	if err != nil {
		c.logger.Error("Request failed",
			zap.String("method", method),
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("request failed: %w", err)
	}

	// Handle API errors
	if resp.IsError() {
		return ParseErrorResponse(
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

	return nil
}
