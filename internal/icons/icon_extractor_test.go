package icons

import (
	"bytes"
	"encoding/binary"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractIcon_Brands(t *testing.T) {
	tests := []struct {
		name       string
		filePath   string
		shouldFind bool
	}{
		{name: "Mozilla Firefox", filePath: "", shouldFind: true},
		{name: "Google Chrome Enterprise", filePath: "", shouldFind: true},
		{name: "Visual Studio Code", filePath: "", shouldFind: true},
		{name: "Git for Windows", filePath: "", shouldFind: true},
		{name: "Slack", filePath: "", shouldFind: true},
		{name: "7-Zip 23.01", filePath: "", shouldFind: true},
		{name: "Docker Desktop", filePath: "", shouldFind: true},
		{name: "Custom Utility", filePath: "/path/to/putty.exe", shouldFind: true},
		{name: "Unknown Application", filePath: "/path/to/unknown.pkg", shouldFind: false},
		{name: "", filePath: "", shouldFind: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ExtractIcon(tt.name, tt.filePath)
			if tt.shouldFind {
				assert.NotEmpty(t, res)
				assert.True(t, strings.HasPrefix(res, "data:image/svg+xml;base64,"))
			} else {
				assert.Empty(t, res)
			}
		})
	}
}

func TestResolveIconURL(t *testing.T) {
	t.Run("existing data URI preserved", func(t *testing.T) {
		custom := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="
		assert.Equal(t, custom, ResolveIconURL(custom, "Firefox"))
	})

	t.Run("brand key resolved", func(t *testing.T) {
		res := ResolveIconURL("firefox", "")
		assert.NotEmpty(t, res)
		assert.True(t, strings.HasPrefix(res, "data:image/svg+xml;base64,"))
	})

	t.Run("brand name resolved when icon empty", func(t *testing.T) {
		res := ResolveIconURL("", "Google Chrome")
		assert.NotEmpty(t, res)
		assert.True(t, strings.HasPrefix(res, "data:image/svg+xml;base64,"))
	})

	t.Run("unknown returns empty string", func(t *testing.T) {
		assert.Equal(t, "", ResolveIconURL("", "Totally Unknown App"))
		assert.Equal(t, "", ResolveIconURL("", ""))
	})
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

// buildTestPE creates a well-formed Portable Executable (PE32 or PE32+) binary in memory
// with a valid .rsrc section and Resource Directory located at the correct DataDirectory[2] offset.
func buildTestPE(t *testing.T, is64Bit bool, iconBytes []byte) []byte {
	t.Helper()
	buf := &bytes.Buffer{}

	// 1. DOS Header (64 bytes)
	dosHeader := make([]byte, 64)
	dosHeader[0] = 'M'
	dosHeader[1] = 'Z'
	peOffset := uint32(128)
	binary.LittleEndian.PutUint32(dosHeader[0x3C:0x40], peOffset)
	buf.Write(dosHeader)

	// Padding up to peOffset
	if pad := int(peOffset) - buf.Len(); pad > 0 {
		buf.Write(make([]byte, pad))
	}

	// 2. PE Signature "PE\x00\x00" (4 bytes)
	buf.WriteString("PE\x00\x00")

	// 3. COFF File Header (20 bytes)
	var machine uint16 = 0x014c // i386
	var optHeaderSize uint16 = 224
	var optMagic uint16 = 0x10b // PE32

	if is64Bit {
		machine = 0x8664 // AMD64
		optHeaderSize = 240
		optMagic = 0x20b // PE32+
	}

	binary.Write(buf, binary.LittleEndian, machine)
	binary.Write(buf, binary.LittleEndian, uint16(1))      // NumberOfSections: 1 (.rsrc)
	binary.Write(buf, binary.LittleEndian, uint32(0))      // TimeDateStamp
	binary.Write(buf, binary.LittleEndian, uint32(0))      // PointerToSymbolTable
	binary.Write(buf, binary.LittleEndian, uint32(0))      // NumberOfSymbols
	binary.Write(buf, binary.LittleEndian, optHeaderSize)  // SizeOfOptionalHeader
	binary.Write(buf, binary.LittleEndian, uint16(0x0002)) // Characteristics: EXECUTABLE_IMAGE

	// 4. Optional Header (optHeaderSize bytes)
	optBuf := make([]byte, optHeaderSize)
	binary.LittleEndian.PutUint16(optBuf[0:2], optMagic)

	rsrcRVA := uint32(0x2000)
	rsrcSize := uint32(0x1000)

	if !is64Bit {
		// PE32: Resource Directory is DataDirectory[2] at offset 112 (96 + 2*8)
		binary.LittleEndian.PutUint32(optBuf[112:116], rsrcRVA)
		binary.LittleEndian.PutUint32(optBuf[116:120], rsrcSize)
	} else {
		// PE32+: Resource Directory is DataDirectory[2] at offset 128 (112 + 2*8)
		binary.LittleEndian.PutUint32(optBuf[128:132], rsrcRVA)
		binary.LittleEndian.PutUint32(optBuf[132:136], rsrcSize)
	}
	buf.Write(optBuf)

	// 5. Section Header for .rsrc (40 bytes)
	secHeader := make([]byte, 40)
	copy(secHeader[0:8], ".rsrc\x00\x00\x00")
	binary.LittleEndian.PutUint32(secHeader[8:12], rsrcSize)       // VirtualSize
	binary.LittleEndian.PutUint32(secHeader[12:16], rsrcRVA)       // VirtualAddress (0x2000)
	binary.LittleEndian.PutUint32(secHeader[16:20], rsrcSize)      // SizeOfRawData
	rsrcRawOffset := uint32(512)                                   // file offset
	binary.LittleEndian.PutUint32(secHeader[20:24], rsrcRawOffset) // PointerToRawData
	binary.LittleEndian.PutUint32(secHeader[36:40], 0x40000040)    // Characteristics
	buf.Write(secHeader)

	// Padding up to rsrcRawOffset (512)
	if pad := int(rsrcRawOffset) - buf.Len(); pad > 0 {
		buf.Write(make([]byte, pad))
	}

	// 6. .rsrc section data
	rsrcData := make([]byte, rsrcSize)

	// Root directory (Type table):
	binary.LittleEndian.PutUint16(rsrcData[14:16], 1) // 1 ID entry
	// Entry 0 at offset 16:
	binary.LittleEndian.PutUint32(rsrcData[16:20], 3)               // RT_ICON = 3
	binary.LittleEndian.PutUint32(rsrcData[20:24], 0x80000000|24)   // points to subdir at offset 24

	// Subdir (Name/ID table) at offset 24:
	binary.LittleEndian.PutUint16(rsrcData[24+14:24+16], 1) // 1 ID entry
	// Entry 0 at offset 40 (24 + 16):
	binary.LittleEndian.PutUint32(rsrcData[40:44], 1)  // ID = 1
	binary.LittleEndian.PutUint32(rsrcData[44:48], 48) // Data entry at offset 48

	// Data Entry at offset 48:
	iconRVA := rsrcRVA + 64 // placed at offset 64 in .rsrc
	binary.LittleEndian.PutUint32(rsrcData[48:52], iconRVA)
	binary.LittleEndian.PutUint32(rsrcData[52:56], uint32(len(iconBytes)))

	// Icon data at offset 64
	copy(rsrcData[64:], iconBytes)

	buf.Write(rsrcData)
	return buf.Bytes()
}

func TestExtractIconFromPE_RealPEHeaders(t *testing.T) {
	pngIcon := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")

	t.Run("PE32 (32-bit) with Resource Directory at offset 112", func(t *testing.T) {
		peData := buildTestPE(t, false, pngIcon)
		tmpDir := t.TempDir()
		exePath := filepath.Join(tmpDir, "test32.exe")
		require.NoError(t, os.WriteFile(exePath, peData, 0755))

		iconURI, err := ExtractIconFromPE(exePath)
		require.NoError(t, err)
		assert.NotEmpty(t, iconURI)
		assert.Contains(t, iconURI, "data:image/png;base64,")
	})

	t.Run("PE32+ (64-bit) with Resource Directory at offset 128", func(t *testing.T) {
		peData := buildTestPE(t, true, pngIcon)
		tmpDir := t.TempDir()
		exePath := filepath.Join(tmpDir, "test64.exe")
		require.NoError(t, os.WriteFile(exePath, peData, 0755))

		iconURI, err := ExtractIconFromPE(exePath)
		require.NoError(t, err)
		assert.NotEmpty(t, iconURI)
		assert.Contains(t, iconURI, "data:image/png;base64,")
	})

	t.Run("non-PE file", func(t *testing.T) {
		tmpDir := t.TempDir()
		exePath := filepath.Join(tmpDir, "corrupted.exe")
		require.NoError(t, os.WriteFile(exePath, []byte("NOT_A_PE_HEADER"), 0755))

		_, err := ExtractIconFromPE(exePath)
		assert.Error(t, err)
	})
}

func TestExtractIconFromMSI_Streaming(t *testing.T) {
	pngIcon := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")

	t.Run("embedded PNG inside MSI stream", func(t *testing.T) {
		tmpDir := t.TempDir()
		msiPath := filepath.Join(tmpDir, "installer.msi")

		// Create dummy MSI file with padding then embedded PNG then trailing data
		var buf bytes.Buffer
		buf.Write(bytes.Repeat([]byte{0x00}, 1024)) // 1KB leading data
		buf.Write(pngIcon)
		buf.Write(bytes.Repeat([]byte{0x00}, 2048)) // 2KB trailing data
		require.NoError(t, os.WriteFile(msiPath, buf.Bytes(), 0644))

		iconURI, err := ExtractIconFromMSI(msiPath)
		require.NoError(t, err)
		assert.NotEmpty(t, iconURI)
		assert.Contains(t, iconURI, "data:image/png;base64,")
	})

	t.Run("embedded ICO inside MSI stream", func(t *testing.T) {
		tmpDir := t.TempDir()
		msiPath := filepath.Join(tmpDir, "installer_ico.msi")

		// Create valid ICO header: 0, 1, 1 (1 image)
		var icoBuf bytes.Buffer
		binary.Write(&icoBuf, binary.LittleEndian, uint16(0))
		binary.Write(&icoBuf, binary.LittleEndian, uint16(1))
		binary.Write(&icoBuf, binary.LittleEndian, uint16(1))
		// Directory entry: width=32, height=32, colors=0, reserved=0, planes=1, bpp=32, bytesInRes=128, offset=22
		icoBuf.WriteByte(32)
		icoBuf.WriteByte(32)
		icoBuf.WriteByte(0)
		icoBuf.WriteByte(0)
		binary.Write(&icoBuf, binary.LittleEndian, uint16(1))
		binary.Write(&icoBuf, binary.LittleEndian, uint16(32))
		binary.Write(&icoBuf, binary.LittleEndian, uint32(128))
		binary.Write(&icoBuf, binary.LittleEndian, uint32(22))
		// DIB data (128 bytes)
		icoBuf.Write(bytes.Repeat([]byte{0xAA}, 128))

		var msiBuf bytes.Buffer
		msiBuf.Write(bytes.Repeat([]byte{0x00}, 512))
		msiBuf.Write(icoBuf.Bytes())
		msiBuf.Write(bytes.Repeat([]byte{0x00}, 512))
		require.NoError(t, os.WriteFile(msiPath, msiBuf.Bytes(), 0644))

		iconURI, err := ExtractIconFromMSI(msiPath)
		require.NoError(t, err)
		assert.NotEmpty(t, iconURI)
		assert.Contains(t, iconURI, "data:image/x-icon;base64,")
	})

	t.Run("no icon found", func(t *testing.T) {
		tmpDir := t.TempDir()
		msiPath := filepath.Join(tmpDir, "empty.msi")
		require.NoError(t, os.WriteFile(msiPath, bytes.Repeat([]byte{0x00}, 1024), 0644))

		_, err := ExtractIconFromMSI(msiPath)
		assert.Error(t, err)
	})
}
