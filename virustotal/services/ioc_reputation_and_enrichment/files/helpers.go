package files

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// progressReader wraps an io.Reader and reports upload progress
type progressReader struct {
	reader     io.Reader
	total      int64
	read       int64
	progressCh chan<- float32
}

// Read implements io.Reader interface and reports progress
func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.read += int64(n)
	if pr.progressCh != nil && pr.total > 0 {
		progress := float32(pr.read) / float32(pr.total) * 100
		pr.progressCh <- progress
	}
	return n, err
}

// determineFileSize attempts to determine the size of the file from various reader types
// Returns the size in bytes, or -1 if the size cannot be determined
func determineFileSize(r io.Reader) int64 {
	switch v := r.(type) {
	case *os.File:
		if stat, err := v.Stat(); err == nil {
			return stat.Size()
		}
	case *bytes.Buffer:
		return int64(v.Len())
	case *bytes.Reader:
		return int64(v.Len())
	case *strings.Reader:
		return int64(v.Len())
	}
	return -1
}

// prepareReader prepares the reader for upload and returns the file size
// If the size cannot be determined from the reader type, it reads the entire
// content into a buffer to determine the size
func prepareReader(r io.Reader) (io.Reader, int64, error) {
	fileSize := determineFileSize(r)
	
	// If size is still unknown, read entire content into buffer
	if fileSize == -1 {
		b := &bytes.Buffer{}
		n, err := io.Copy(b, r)
		if err != nil {
			return nil, -1, fmt.Errorf("failed to read file content: %w", err)
		}
		fileSize = n
		r = b
	}
	
	return r, fileSize, nil
}

// validateFileSize checks if the file size is within acceptable limits
func validateFileSize(size int64) error {
	if size > MaxFileSize {
		return fmt.Errorf("file size (%d bytes) exceeds maximum allowed size of %d bytes (650MB)", size, MaxFileSize)
	}
	if size <= 0 {
		return fmt.Errorf("invalid file size: %d bytes", size)
	}
	return nil
}

// shouldUseLargeFileEndpoint determines if the large file upload endpoint should be used
func shouldUseLargeFileEndpoint(size int64) bool {
	return size > MaxPayloadSize
}
