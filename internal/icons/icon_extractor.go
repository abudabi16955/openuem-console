package icons

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// BrandMapping maps common application names or keywords to standard icon names.
var brandKeywords = map[string]string{
	"firefox":       "firefox",
	"mozilla":       "firefox",
	"chrome":        "chrome",
	"chromium":      "chrome",
	"google chrome": "chrome",
	"edge":          "globe",
	"msedge":        "globe",
	"code":          "code",
	"vscode":        "code",
	"visual studio": "code",
	"git":           "git",
	"github":        "git",
	"slack":         "slack",
	"discord":       "discord",
	"teams":         "teams",
	"zoom":          "video",
	"vlc":           "play",
	"videolan":      "play",
	"7-zip":         "archive",
	"7zip":          "archive",
	"winrar":        "archive",
	"notepad":       "file-text",
	"docker":        "server",
	"libreoffice":   "file-text",
	"openoffice":    "file-text",
	"python":        "terminal",
	"node":          "terminal",
	"nodejs":        "terminal",
	"putty":         "terminal",
	"powershell":    "terminal",
	"terminal":      "terminal",
	"spotify":       "music",
	"wireshark":     "activity",
	"dbeaver":       "database",
	"pgadmin":       "database",
}

// ExtractIcon attempts to extract or detect an icon based on package name, brands, or binary file.
// If no matching brand or binary icon is found, it returns an empty string ("").
func ExtractIcon(name, filePath string) string {
	// 1. Check brand matching by package name
	lowerName := strings.ToLower(name)
	for keyword, iconName := range brandKeywords {
		if strings.Contains(lowerName, keyword) {
			return iconName
		}
	}

	// 2. Check brand matching by filename
	if filePath != "" {
		baseName := strings.ToLower(filepath.Base(filePath))
		for keyword, iconName := range brandKeywords {
			if strings.Contains(baseName, keyword) {
				return iconName
			}
		}

		// 3. Extract from binary if file exists
		ext := strings.ToLower(filepath.Ext(filePath))
		switch ext {
		case ".exe":
			if iconData, err := ExtractIconFromPE(filePath); err == nil && iconData != "" {
				return iconData
			}
		case ".msi":
			if iconData, err := ExtractIconFromMSI(filePath); err == nil && iconData != "" {
				return iconData
			}
		}
	}

	// Default fallback: empty icon
	return ""
}

// ProcessUploadedIcon processes an uploaded icon image file and returns a base64 data URI.
func ProcessUploadedIcon(fileHeader *multipart.FileHeader) (string, error) {
	if fileHeader == nil {
		return "", nil
	}

	// Limit to max 2MB
	if fileHeader.Size > 2*1024*1024 {
		return "", fmt.Errorf("icon file too large (max 2MB)")
	}

	file, err := fileHeader.Open()
	if err != nil {
		return "", fmt.Errorf("could not open uploaded icon: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("could not read uploaded icon: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))
	mimeType := ""

	switch ext {
	case ".png":
		mimeType = "image/png"
	case ".ico":
		mimeType = "image/x-icon"
	case ".svg":
		mimeType = "image/svg+xml"
	case ".jpg", ".jpeg":
		mimeType = "image/jpeg"
	case ".webp":
		mimeType = "image/webp"
	default:
		sniffed := http.DetectContentType(data)
		if strings.HasPrefix(sniffed, "image/") {
			mimeType = sniffed
		} else {
			return "", fmt.Errorf("unsupported icon format: %s", ext)
		}
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, encoded), nil
}

// ExtractIconFromPE parses a Portable Executable (.exe) and extracts its main icon as base64 data URI.
func ExtractIconFromPE(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// 1. Read DOS header
	var dosHeader [64]byte
	if _, err := io.ReadFull(f, dosHeader[:]); err != nil {
		return "", err
	}
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return "", fmt.Errorf("not a valid PE file: invalid MZ header")
	}

	peOffset := binary.LittleEndian.Uint32(dosHeader[0x3C:0x40])
	if _, err := f.Seek(int64(peOffset), io.SeekStart); err != nil {
		return "", err
	}

	// 2. Read PE signature
	var peSig [4]byte
	if _, err := io.ReadFull(f, peSig[:]); err != nil {
		return "", err
	}
	if string(peSig[:]) != "PE\x00\x00" {
		return "", fmt.Errorf("not a valid PE signature")
	}

	// 3. Read COFF File Header (20 bytes)
	var coffHeader struct {
		Machine              uint16
		NumberOfSections     uint16
		TimeDateStamp        uint32
		PointerToSymbolTable uint32
		NumberOfSymbols      uint32
		SizeOfOptionalHeader uint16
		Characteristics      uint16
	}
	if err := binary.Read(f, binary.LittleEndian, &coffHeader); err != nil {
		return "", err
	}

	if coffHeader.SizeOfOptionalHeader == 0 {
		return "", fmt.Errorf("no optional header")
	}

	// 4. Read Optional Header Magic to check 32-bit or 64-bit
	var optMagic uint16
	if err := binary.Read(f, binary.LittleEndian, &optMagic); err != nil {
		return "", err
	}

	var rsrcRVA uint32
	var rsrcSize uint32

	// Resource Directory is DataDirectory[2] in the Optional Header.
	// Data directories start at offset 96 for PE32 and offset 112 for PE32+.
	// Each entry is 8 bytes (RVA uint32, Size uint32).
	// PE32:  Resource Directory is at 96 + 2*8 = 112 (RVA) and 116 (Size).
	// PE32+: Resource Directory is at 112 + 2*8 = 128 (RVA) and 132 (Size).
	if optMagic == 0x10b { // PE32
		if _, err := f.Seek(int64(peOffset)+4+20+112, io.SeekStart); err != nil {
			return "", err
		}
		var rsrcEntry struct {
			RVA  uint32
			Size uint32
		}
		if err := binary.Read(f, binary.LittleEndian, &rsrcEntry); err != nil {
			return "", err
		}
		rsrcRVA = rsrcEntry.RVA
		rsrcSize = rsrcEntry.Size
	} else if optMagic == 0x20b { // PE32+ (64-bit)
		if _, err := f.Seek(int64(peOffset)+4+20+128, io.SeekStart); err != nil {
			return "", err
		}
		var rsrcEntry struct {
			RVA  uint32
			Size uint32
		}
		if err := binary.Read(f, binary.LittleEndian, &rsrcEntry); err != nil {
			return "", err
		}
		rsrcRVA = rsrcEntry.RVA
		rsrcSize = rsrcEntry.Size
	} else {
		return "", fmt.Errorf("unknown optional header magic: %x", optMagic)
	}

	if rsrcRVA == 0 || rsrcSize == 0 {
		return "", fmt.Errorf("no resource directory found")
	}

	// 5. Read Section Headers to locate .rsrc section
	sectionStart := int64(peOffset) + 4 + 20 + int64(coffHeader.SizeOfOptionalHeader)
	if _, err := f.Seek(sectionStart, io.SeekStart); err != nil {
		return "", err
	}

	var rsrcRawOffset uint32
	var rsrcSectionRVA uint32
	var foundRsrc bool

	for i := 0; i < int(coffHeader.NumberOfSections); i++ {
		var sec struct {
			Name                 [8]byte
			VirtualSize          uint32
			VirtualAddress       uint32
			SizeOfRawData        uint32
			PointerToRawData     uint32
			PointerToRelocations uint32
			PointerToLinenumbers uint32
			NumberOfRelocations  uint16
			NumberOfLinenumbers  uint16
			Characteristics      uint32
		}
		if err := binary.Read(f, binary.LittleEndian, &sec); err != nil {
			break
		}

		if rsrcRVA >= sec.VirtualAddress && rsrcRVA < sec.VirtualAddress+sec.VirtualSize {
			rsrcRawOffset = sec.PointerToRawData
			rsrcSectionRVA = sec.VirtualAddress
			foundRsrc = true
			break
		}
	}

	if !foundRsrc {
		return "", fmt.Errorf("could not locate .rsrc section")
	}

	// 6. Read .rsrc section data
	rsrcData := make([]byte, rsrcSize)
	if _, err := f.Seek(int64(rsrcRawOffset), io.SeekStart); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(f, rsrcData); err != nil {
		return "", err
	}

	iconBytes, err := findFirstIconData(rsrcData, rsrcSectionRVA, rsrcRawOffset, f)
	if err != nil || len(iconBytes) == 0 {
		return "", err
	}

	if len(iconBytes) > 8 && bytes.Equal(iconBytes[:8], []byte("\x89PNG\r\n\x1a\n")) {
		return "data:image/png;base64," + base64.StdEncoding.EncodeToString(iconBytes), nil
	}

	icoFile := wrapDIBIntoICO(iconBytes)
	return "data:image/x-icon;base64," + base64.StdEncoding.EncodeToString(icoFile), nil
}

func findFirstIconData(rsrc []byte, rsrcSectionRVA, rsrcRawOffset uint32, f *os.File) ([]byte, error) {
	if len(rsrc) < 16 {
		return nil, fmt.Errorf("resource table too short")
	}

	numNamed := binary.LittleEndian.Uint16(rsrc[12:14])
	numID := binary.LittleEndian.Uint16(rsrc[14:16])
	totalEntries := int(numNamed) + int(numID)

	for i := 0; i < totalEntries; i++ {
		entryOffset := 16 + i*8
		if entryOffset+8 > len(rsrc) {
			break
		}
		typeID := binary.LittleEndian.Uint32(rsrc[entryOffset : entryOffset+4])
		subOffset := binary.LittleEndian.Uint32(rsrc[entryOffset+4 : entryOffset+8])

		// RT_ICON = 3
		if typeID == 3 && (subOffset&0x80000000) != 0 {
			rawIcon, err := extractIconFromSubdir(rsrc, subOffset&0x7FFFFFFF, rsrcSectionRVA, rsrcRawOffset, f)
			if err == nil && len(rawIcon) > 0 {
				return rawIcon, nil
			}
		}
	}

	return nil, fmt.Errorf("no icon found in resource directory")
}

func extractIconFromSubdir(rsrc []byte, dirOffset uint32, rsrcSectionRVA, rsrcRawOffset uint32, f *os.File) ([]byte, error) {
	if int(dirOffset)+16 > len(rsrc) {
		return nil, fmt.Errorf("invalid directory offset")
	}

	numNamed := binary.LittleEndian.Uint16(rsrc[dirOffset+12 : dirOffset+14])
	numID := binary.LittleEndian.Uint16(rsrc[dirOffset+14 : dirOffset+16])
	totalEntries := int(numNamed) + int(numID)

	for i := 0; i < totalEntries; i++ {
		entryOffset := int(dirOffset) + 16 + i*8
		if entryOffset+8 > len(rsrc) {
			break
		}
		subOffset := binary.LittleEndian.Uint32(rsrc[entryOffset+4 : entryOffset+8])
		if (subOffset & 0x80000000) != 0 {
			langOffset := subOffset & 0x7FFFFFFF
			if int(langOffset)+16 > len(rsrc) {
				continue
			}
			dataEntryOffset := int(langOffset) + 16 + 4
			if dataEntryOffset+4 > len(rsrc) {
				continue
			}
			leafOffset := binary.LittleEndian.Uint32(rsrc[dataEntryOffset : dataEntryOffset+4])
			if (leafOffset & 0x80000000) == 0 {
				return readDataEntry(rsrc, leafOffset, rsrcSectionRVA, rsrcRawOffset, f)
			}
		} else {
			return readDataEntry(rsrc, subOffset, rsrcSectionRVA, rsrcRawOffset, f)
		}
	}
	return nil, fmt.Errorf("no icon data leaf found")
}

func readDataEntry(rsrc []byte, dataEntryOffset uint32, rsrcSectionRVA, rsrcRawOffset uint32, f *os.File) ([]byte, error) {
	if int(dataEntryOffset)+16 > len(rsrc) {
		return nil, fmt.Errorf("data entry out of bounds")
	}
	dataRVA := binary.LittleEndian.Uint32(rsrc[dataEntryOffset : dataEntryOffset+4])
	dataSize := binary.LittleEndian.Uint32(rsrc[dataEntryOffset+4 : dataEntryOffset+8])

	if dataSize == 0 || dataSize > 10*1024*1024 {
		return nil, fmt.Errorf("invalid data size: %d", dataSize)
	}

	fileOffset := int64(dataRVA - rsrcSectionRVA + rsrcRawOffset)
	buf := make([]byte, dataSize)
	if _, err := f.Seek(fileOffset, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func wrapDIBIntoICO(dib []byte) []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint16(1))
	binary.Write(&buf, binary.LittleEndian, uint16(1))

	var width, height uint8 = 32, 32
	var planes, bitCount uint16 = 1, 32

	if len(dib) >= 40 {
		w := binary.LittleEndian.Uint32(dib[4:8])
		h := binary.LittleEndian.Uint32(dib[8:12]) / 2
		p := binary.LittleEndian.Uint16(dib[12:14])
		b := binary.LittleEndian.Uint16(dib[14:16])
		if w > 0 && w <= 256 {
			width = uint8(w % 256)
		}
		if h > 0 && h <= 256 {
			height = uint8(h % 256)
		}
		if p > 0 {
			planes = p
		}
		if b > 0 {
			bitCount = b
		}
	}

	buf.WriteByte(width)
	buf.WriteByte(height)
	buf.WriteByte(0)
	buf.WriteByte(0)
	binary.Write(&buf, binary.LittleEndian, planes)
	binary.Write(&buf, binary.LittleEndian, bitCount)
	binary.Write(&buf, binary.LittleEndian, uint32(len(dib)))
	binary.Write(&buf, binary.LittleEndian, uint32(22))

	buf.Write(dib)
	return buf.Bytes()
}

// ExtractIconFromMSI extracts an embedded icon (PNG or ICO) from an MSI package
// using streaming buffered search with a memory-safe limit (max 64MB scan, 512KB buffer).
func ExtractIconFromMSI(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return "", err
	}

	// Limit scan to 64MB to prevent excessive I/O on huge files
	maxScan := int64(64 * 1024 * 1024)
	if fi.Size() < maxScan {
		maxScan = fi.Size()
	}

	const chunkSize = 512 * 1024
	const overlap = 64 // overlap to ensure magic bytes aren't split across chunk boundaries
	buf := make([]byte, chunkSize)

	pngMagic := []byte("\x89PNG\r\n\x1a\n")
	iendMagic := []byte("IEND\xaeB`\x82")
	icoMagic := []byte("\x00\x00\x01\x00")

	var offset int64 = 0

	for offset < maxScan {
		readSize := chunkSize
		if offset+int64(readSize) > maxScan {
			readSize = int(maxScan - offset)
		}
		if readSize <= overlap {
			break
		}

		n, err := f.ReadAt(buf[:readSize], offset)
		if n == 0 || (err != nil && err != io.EOF) {
			break
		}
		currData := buf[:n]

		// 1. Check for PNG in currData
		searchIdx := 0
		for {
			idx := bytes.Index(currData[searchIdx:], pngMagic)
			if idx == -1 {
				break
			}
			pngStartInChunk := searchIdx + idx
			absPngStart := offset + int64(pngStartInChunk)

			// Read up to 2MB from absPngStart to find IEND
			readLimit := int64(2 * 1024 * 1024)
			if absPngStart+readLimit > fi.Size() {
				readLimit = fi.Size() - absPngStart
			}

			if readLimit > 64 {
				candBuf := make([]byte, readLimit)
				if nCand, err := f.ReadAt(candBuf, absPngStart); err == nil || err == io.EOF {
					candData := candBuf[:nCand]
					if endIdx := bytes.Index(candData, iendMagic); endIdx != -1 {
						totalLen := endIdx + len(iendMagic)
						pngData := candData[:totalLen]
						if len(pngData) > 64 && len(pngData) <= 2*1024*1024 {
							return "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngData), nil
						}
					}
				}
			}
			searchIdx = pngStartInChunk + len(pngMagic)
		}

		// 2. Check for ICO in currData
		searchIdx = 0
		for {
			idx := bytes.Index(currData[searchIdx:], icoMagic)
			if idx == -1 || searchIdx+idx+22 > len(currData) {
				break
			}
			icoStartInChunk := searchIdx + idx
			absIcoStart := offset + int64(icoStartInChunk)

			// Read header
			numImages := binary.LittleEndian.Uint16(currData[icoStartInChunk+4 : icoStartInChunk+6])
			if numImages >= 1 && numImages <= 16 {
				bytesInRes := binary.LittleEndian.Uint32(currData[icoStartInChunk+14 : icoStartInChunk+18])
				imageOffset := binary.LittleEndian.Uint32(currData[icoStartInChunk+18 : icoStartInChunk+22])
				totalExpected := int(imageOffset) + int(bytesInRes)

				if imageOffset >= 22 && totalExpected <= 2*1024*1024 && bytesInRes > 64 && bytesInRes < 1024*1024 {
					if absIcoStart+int64(totalExpected) <= fi.Size() {
						icoBuf := make([]byte, totalExpected)
						if _, err := f.ReadAt(icoBuf, absIcoStart); err == nil || err == io.EOF {
							return "data:image/x-icon;base64," + base64.StdEncoding.EncodeToString(icoBuf), nil
						}
					}
				}
			}
			searchIdx = icoStartInChunk + 4
		}

		// Advance offset with overlap
		advance := int64(n - overlap)
		if advance <= 0 {
			break
		}
		offset += advance
	}

	return "", fmt.Errorf("no embedded icon found in MSI")
}
