package icons

import (
	"bytes"
	"mime/multipart"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractIcon_Brands(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected string
	}{
		{name: "Mozilla Firefox", filePath: "", expected: "firefox"},
		{name: "Google Chrome Enterprise", filePath: "", expected: "chrome"},
		{name: "Visual Studio Code", filePath: "", expected: "code"},
		{name: "Git for Windows", filePath: "", expected: "git"},
		{name: "Slack", filePath: "", expected: "slack"},
		{name: "7-Zip 23.01", filePath: "", expected: "archive"},
		{name: "Docker Desktop", filePath: "", expected: "server"},
		{name: "Custom Utility", filePath: "/path/to/putty.exe", expected: "terminal"},
		{name: "Unknown Application", filePath: "/path/to/unknown.pkg", expected: ""},
		{name: "", filePath: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ExtractIcon(tt.name, tt.filePath)
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestProcessUploadedIcon(t *testing.T) {
	t.Run("nil header", func(t *testing.T) {
		res, err := ProcessUploadedIcon(nil)
		assert.NoError(t, err)
		assert.Empty(t, res)
	})

	t.Run("valid png upload", func(t *testing.T) {
		pngContent := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "test.png")
		require.NoError(t, os.WriteFile(filePath, pngContent, 0644))

		file, err := os.Open(filePath)
		require.NoError(t, err)
		defer file.Close()

		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		part, err := writer.CreateFormFile("icon_file", "test.png")
		require.NoError(t, err)
		_, err = part.Write(pngContent)
		require.NoError(t, err)
		require.NoError(t, writer.Close())

		reader := multipart.NewReader(&body, writer.Boundary())
		form, err := reader.ReadForm(1024 * 1024)
		require.NoError(t, err)

		files := form.File["icon_file"]
		require.Len(t, files, 1)

		res, err := ProcessUploadedIcon(files[0])
		assert.NoError(t, err)
		assert.Contains(t, res, "data:image/png;base64,")
	})
}
