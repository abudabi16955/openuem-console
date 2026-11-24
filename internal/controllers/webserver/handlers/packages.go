package handlers

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/selfservicepackage"
	"github.com/open-uem/openuem-console/internal/icons"
	"github.com/open-uem/openuem-console/internal/views/filters"
	"github.com/open-uem/openuem-console/internal/views/packages_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/utils"
)

type SelfServiceNotification struct {
	Action     string    `json:"action"`
	PackageID  string    `json:"package_id,omitempty"`
	ConsoleURL string    `json:"console_url,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

func (h *Handler) getPackagesDir() string {
	baseDir := h.DownloadDir
	if baseDir == "" {
		baseDir = filepath.Join(os.TempDir(), "openuem")
	}
	dir := filepath.Join(filepath.Dir(baseDir), "packages")
	_ = os.MkdirAll(dir, 0750)
	return dir
}

func (h *Handler) getConsoleURL() string {
	if h.ReverseProxyServer != "" {
		url := h.ReverseProxyServer
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}
		return strings.TrimSuffix(url, "/")
	}
	server := h.ServerName
	if server == "" {
		server = "localhost"
	}
	port := h.ConsolePort
	if port == "" {
		port = "8080"
	}
	return fmt.Sprintf("https://%s:%s", server, port)
}

func (h *Handler) notifySelfServiceUpdate(action string, packageID string) {
	if h.NATSConnection == nil || !h.NATSConnection.IsConnected() {
		return
	}
	msg := SelfServiceNotification{
		Action:     action,
		PackageID:  packageID,
		ConsoleURL: h.getConsoleURL(),
		Timestamp:  time.Now().UTC(),
	}
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[ERROR]: could not marshal selfservice notification: %v", err)
		return
	}
	if err := h.NATSConnection.Publish("agent.selfservice.update", data); err != nil {
		log.Printf("[ERROR]: could not publish selfservice update to NATS: %v", err)
	}
}

func (h *Handler) isAuthorizedForPackageDownload(c echo.Context) bool {
	// 1. Check Console Session
	if h.SessionManager != nil && h.SessionManager.Manager != nil {
		uid := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
		if uid != "" {
			if user, err := h.Model.GetUserById(uid); err == nil && user != nil {
				return true
			}
		}
	}

	// 2. Check mTLS peer certificate
	var cert *x509.Certificate
	if c.Request().TLS != nil && len(c.Request().TLS.PeerCertificates) > 0 {
		cert = c.Request().TLS.PeerCertificates[0]
	} else {
		clientEncodedCert := c.Request().Header.Get("Client-Cert")
		if clientEncodedCert != "" {
			cleanBase64 := ""
			if strings.Contains(clientEncodedCert, "BEGIN CERTIFICATE") {
				cleanBase64 = strings.TrimPrefix(clientEncodedCert, ":-----BEGIN CERTIFICATE----- ")
				cleanBase64 = strings.TrimSuffix(cleanBase64, " -----END CERTIFICATE-----:")
				cleanBase64 = strings.ReplaceAll(cleanBase64, " ", "")
			} else {
				cleanBase64 = strings.Trim(clientEncodedCert, ":")
			}
			decoded, err := base64.StdEncoding.DecodeString(cleanBase64)
			if err == nil {
				cert, _ = x509.ParseCertificate(decoded)
			}
		}
	}

	if cert != nil {
		if h.CACertPath != "" {
			caCert, err := utils.ReadPEMCertificate(h.CACertPath)
			if err == nil && caCert != nil {
				trustedCAPool := x509.NewCertPool()
				trustedCAPool.AddCert(caCert)
				vOpts := x509.VerifyOptions{
					Roots:     trustedCAPool,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}
				if _, err := cert.Verify(vOpts); err == nil {
					return true
				}
			}
		} else {
			return true
		}
	}

	return false
}

func (h *Handler) Packages(c echo.Context) error {
	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	itemsPerPage, err := h.Model.GetDefaultItemsPerPage()
	if err != nil {
		itemsPerPage = 10
	}

	p := partials.NewPaginationAndSort(itemsPerPage)
	p.GetPaginationAndSortParams(c.FormValue("page"), c.FormValue("pageSize"), c.FormValue("sortBy"), c.FormValue("sortOrder"), c.FormValue("currentSortBy"), itemsPerPage)

	f := filters.SelfServicePackageFilter{
		Search:   c.FormValue("search"),
		Category: c.FormValue("category"),
		Type:     c.FormValue("type"),
		Enabled:  c.FormValue("enabled"),
	}

	p.NItems, err = h.Model.CountSelfServicePackages(c.Request().Context(), f)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(err.Error(), false))
	}

	pkgs, err := h.Model.GetSelfServicePackagesByPage(c.Request().Context(), p, f)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(err.Error(), false))
	}

	return RenderView(c, packages_views.PackagesIndex(" | Packages", packages_views.Packages(c, p, f, pkgs, itemsPerPage, commonInfo), commonInfo))
}

func (h *Handler) SavePackage(c echo.Context) error {
	name := strings.TrimSpace(c.FormValue("name"))
	if name == "" {
		return RenderError(c, partials.ErrorMessage("Package name is required", false))
	}

	description := c.FormValue("description")
	category := strings.TrimSpace(c.FormValue("category"))
	if category == "" {
		category = "General"
	}
	version := strings.TrimSpace(c.FormValue("version"))
	pkgTypeStr := c.FormValue("package_type")
	sourceTypeStr := c.FormValue("source_type")
	sourceURL := strings.TrimSpace(c.FormValue("source_url"))
	checksum := strings.TrimSpace(c.FormValue("checksum"))
	execContextStr := c.FormValue("execution_context")
	silentArgs := c.FormValue("silent_args")
	icon := strings.TrimSpace(c.FormValue("icon"))
	enabled := c.FormValue("enabled") == "on" || c.FormValue("enabled") == "true"

	pkgType := selfservicepackage.PackageType(pkgTypeStr)
	if err := selfservicepackage.PackageTypeValidator(pkgType); err != nil {
		return RenderError(c, partials.ErrorMessage("Invalid package type", false))
	}

	sourceType := selfservicepackage.SourceType(sourceTypeStr)
	if err := selfservicepackage.SourceTypeValidator(sourceType); err != nil {
		return RenderError(c, partials.ErrorMessage("Invalid source type", false))
	}

	execContext := selfservicepackage.ExecutionContext(execContextStr)
	if err := selfservicepackage.ExecutionContextValidator(execContext); err != nil {
		return RenderError(c, partials.ErrorMessage("Invalid execution context", false))
	}

	filePath := ""
	if sourceType == selfservicepackage.SourceTypeUpload {
		file, err := c.FormFile("file")
		if err != nil {
			return RenderError(c, partials.ErrorMessage("Please select a file to upload", false))
		}

		ext := strings.ToLower(filepath.Ext(file.Filename))
		switch pkgType {
		case selfservicepackage.PackageTypeMsi:
			if ext != ".msi" {
				return RenderError(c, partials.ErrorMessage("File extension must be .msi for MSI package type", false))
			}
		case selfservicepackage.PackageTypeExe:
			if ext != ".exe" {
				return RenderError(c, partials.ErrorMessage("File extension must be .exe for EXE package type", false))
			}
		case selfservicepackage.PackageTypeZip:
			if ext != ".zip" {
				return RenderError(c, partials.ErrorMessage("File extension must be .zip for ZIP package type", false))
			}
		}

		src, err := file.Open()
		if err != nil {
			return RenderError(c, partials.ErrorMessage(fmt.Sprintf("Could not open uploaded file: %v", err), false))
		}
		defer src.Close()

		destFilename := fmt.Sprintf("%s_%s", uuid.New().String(), filepath.Base(file.Filename))
		destPath := filepath.Join(h.getPackagesDir(), destFilename)
		dst, err := os.Create(destPath)
		if err != nil {
			return RenderError(c, partials.ErrorMessage(fmt.Sprintf("Could not save package file: %v", err), false))
		}
		defer dst.Close()

		hasher := sha256.New()
		writer := io.MultiWriter(dst, hasher)
		if _, err := io.Copy(writer, src); err != nil {
			os.Remove(destPath)
			return RenderError(c, partials.ErrorMessage(fmt.Sprintf("Could not write package file: %v", err), false))
		}

		// Checksum is 100% computed by server after upload
		calcChecksum := hex.EncodeToString(hasher.Sum(nil))
		filePath = destPath
		checksum = calcChecksum
	} else if sourceType == selfservicepackage.SourceTypeHTTPS {
		if pkgType != selfservicepackage.PackageTypeWinget && sourceURL == "" {
			return RenderError(c, partials.ErrorMessage("Source URL is required for HTTPS source type", false))
		}
	}

	// Process uploaded custom icon or auto-extract icon
	if iconFile, err := c.FormFile("icon_file"); err == nil && iconFile != nil {
		if uploadedIcon, err := icons.ProcessUploadedIcon(iconFile); err == nil && uploadedIcon != "" {
			icon = uploadedIcon
		}
	} else if icon == "" {
		icon = icons.ExtractIcon(name, filePath)
	}

	createdPkg, err := h.Model.CreateSelfServicePackage(
		c.Request().Context(),
		name,
		description,
		category,
		version,
		pkgType,
		sourceType,
		sourceURL,
		filePath,
		checksum,
		execContext,
		silentArgs,
		icon,
		enabled,
	)
	if err != nil {
		if filePath != "" {
			os.Remove(filePath)
		}
		return RenderError(c, partials.ErrorMessage(fmt.Sprintf("Could not create package: %v", err), false))
	}

	h.notifySelfServiceUpdate("create", createdPkg.ID.String())

	redirectURL := "/packages"
	if commonInfo, err := h.GetCommonInfo(c); err == nil && commonInfo != nil {
		redirectURL = partials.GetNavigationUrl(commonInfo, "/packages")
	}
	c.Response().Header().Set("HX-Redirect", redirectURL)
	return c.String(http.StatusOK, "")
}

func (h *Handler) UpdatePackage(c echo.Context) error {
	idStr := c.Param("id")
	if idStr == "" {
		idStr = c.FormValue("id")
	}

	pkgID, err := uuid.Parse(idStr)
	if err != nil {
		return RenderError(c, partials.ErrorMessage("Invalid package ID", false))
	}

	existingPkg, err := h.Model.GetSelfServicePackageByID(c.Request().Context(), pkgID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage("Package not found", false))
	}

	name := strings.TrimSpace(c.FormValue("name"))
	if name == "" {
		return RenderError(c, partials.ErrorMessage("Package name is required", false))
	}

	description := c.FormValue("description")
	category := strings.TrimSpace(c.FormValue("category"))
	if category == "" {
		category = "General"
	}
	version := strings.TrimSpace(c.FormValue("version"))
	pkgTypeStr := c.FormValue("package_type")
	sourceTypeStr := c.FormValue("source_type")
	sourceURL := strings.TrimSpace(c.FormValue("source_url"))
	checksum := strings.TrimSpace(c.FormValue("checksum"))
	execContextStr := c.FormValue("execution_context")
	silentArgs := c.FormValue("silent_args")
	icon := strings.TrimSpace(c.FormValue("icon"))
	enabled := c.FormValue("enabled") == "on" || c.FormValue("enabled") == "true"

	pkgType := selfservicepackage.PackageType(pkgTypeStr)
	if err := selfservicepackage.PackageTypeValidator(pkgType); err != nil {
		return RenderError(c, partials.ErrorMessage("Invalid package type", false))
	}

	sourceType := selfservicepackage.SourceType(sourceTypeStr)
	if err := selfservicepackage.SourceTypeValidator(sourceType); err != nil {
		return RenderError(c, partials.ErrorMessage("Invalid source type", false))
	}

	execContext := selfservicepackage.ExecutionContext(execContextStr)
	if err := selfservicepackage.ExecutionContextValidator(execContext); err != nil {
		return RenderError(c, partials.ErrorMessage("Invalid execution context", false))
	}

	filePath := existingPkg.FilePath
	if checksum == "" {
		checksum = existingPkg.ChecksumSha256
	}

	file, fileErr := c.FormFile("file")
	if fileErr == nil && file != nil {
		ext := strings.ToLower(filepath.Ext(file.Filename))
		switch pkgType {
		case selfservicepackage.PackageTypeMsi:
			if ext != ".msi" {
				return RenderError(c, partials.ErrorMessage("File extension must be .msi for MSI package type", false))
			}
		case selfservicepackage.PackageTypeExe:
			if ext != ".exe" {
				return RenderError(c, partials.ErrorMessage("File extension must be .exe for EXE package type", false))
			}
		case selfservicepackage.PackageTypeZip:
			if ext != ".zip" {
				return RenderError(c, partials.ErrorMessage("File extension must be .zip for ZIP package type", false))
			}
		}

		src, err := file.Open()
		if err != nil {
			return RenderError(c, partials.ErrorMessage(fmt.Sprintf("Could not open uploaded file: %v", err), false))
		}
		defer src.Close()

		destFilename := fmt.Sprintf("%s_%s", uuid.New().String(), filepath.Base(file.Filename))
		destPath := filepath.Join(h.getPackagesDir(), destFilename)
		dst, err := os.Create(destPath)
		if err != nil {
			return RenderError(c, partials.ErrorMessage(fmt.Sprintf("Could not save package file: %v", err), false))
		}
		defer dst.Close()

		hasher := sha256.New()
		writer := io.MultiWriter(dst, hasher)
		if _, err := io.Copy(writer, src); err != nil {
			os.Remove(destPath)
			return RenderError(c, partials.ErrorMessage(fmt.Sprintf("Could not write package file: %v", err), false))
		}

		// Compute sha256 100% on server
		calcChecksum := hex.EncodeToString(hasher.Sum(nil))
		if existingPkg.FilePath != "" && existingPkg.FilePath != destPath {
			_ = os.Remove(existingPkg.FilePath)
		}

		filePath = destPath
		checksum = calcChecksum
	}

	// Process uploaded custom icon or auto-extract
	if iconFile, err := c.FormFile("icon_file"); err == nil && iconFile != nil {
		if uploadedIcon, err := icons.ProcessUploadedIcon(iconFile); err == nil && uploadedIcon != "" {
			icon = uploadedIcon
		}
	} else if icon == "" {
		if existingPkg.Icon != "" {
			icon = existingPkg.Icon
		} else {
			icon = icons.ExtractIcon(name, filePath)
		}
	}

	_, err = h.Model.UpdateSelfServicePackage(
		c.Request().Context(),
		pkgID,
		name,
		description,
		category,
		version,
		pkgType,
		sourceType,
		sourceURL,
		filePath,
		checksum,
		execContext,
		silentArgs,
		icon,
		enabled,
	)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(fmt.Sprintf("Could not update package: %v", err), false))
	}

	h.notifySelfServiceUpdate("update", pkgID.String())

	redirectURL := "/packages"
	if commonInfo, err := h.GetCommonInfo(c); err == nil && commonInfo != nil {
		redirectURL = partials.GetNavigationUrl(commonInfo, "/packages")
	}
	c.Response().Header().Set("HX-Redirect", redirectURL)
	return c.String(http.StatusOK, "")
}

func (h *Handler) DeletePackage(c echo.Context) error {
	idStr := c.Param("id")
	if idStr == "" {
		idStr = c.FormValue("id")
	}

	pkgID, err := uuid.Parse(idStr)
	if err != nil {
		return RenderError(c, partials.ErrorMessage("Invalid package ID", false))
	}

	existingPkg, err := h.Model.GetSelfServicePackageByID(c.Request().Context(), pkgID)
	if err == nil && existingPkg != nil {
		if existingPkg.FilePath != "" {
			_ = os.Remove(existingPkg.FilePath)
		}
	}

	if err := h.Model.DeleteSelfServicePackage(c.Request().Context(), pkgID); err != nil {
		return RenderError(c, partials.ErrorMessage(fmt.Sprintf("Could not delete package: %v", err), false))
	}

	h.notifySelfServiceUpdate("delete", pkgID.String())

	redirectURL := "/packages"
	if commonInfo, err := h.GetCommonInfo(c); err == nil && commonInfo != nil {
		redirectURL = partials.GetNavigationUrl(commonInfo, "/packages")
	}
	c.Response().Header().Set("HX-Redirect", redirectURL)
	return c.String(http.StatusOK, "")
}

func (h *Handler) DownloadPackage(c echo.Context) error {
	if !h.isAuthorizedForPackageDownload(c) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized: valid console session or agent mTLS certificate required")
	}

	idStr := c.Param("id")
	pkgID, err := uuid.Parse(idStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid package ID")
	}

	pkg, err := h.Model.GetSelfServicePackageByID(c.Request().Context(), pkgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Package not found")
	}

	if pkg.SourceType == selfservicepackage.SourceTypeHTTPS && pkg.SourceURL != "" {
		return c.Redirect(http.StatusFound, pkg.SourceURL)
	}

	if pkg.FilePath == "" {
		return echo.NewHTTPError(http.StatusNotFound, "Package file not specified")
	}

	if _, err := os.Stat(pkg.FilePath); os.IsNotExist(err) {
		return echo.NewHTTPError(http.StatusNotFound, "Package file not found on disk")
	}

	if pkg.ChecksumSha256 != "" {
		c.Response().Header().Set("X-Checksum-SHA256", pkg.ChecksumSha256)
	}

	filename := filepath.Base(pkg.FilePath)
	if idx := strings.Index(filename, "_"); idx != -1 {
		filename = filename[idx+1:]
	}

	return c.Attachment(pkg.FilePath, filename)
}

func (h *Handler) APIGetPackages(c echo.Context) error {
	if !h.isAuthorizedForPackageDownload(c) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	pkgs, err := h.Model.GetAllSelfServicePackages(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Could not retrieve packages: %v", err))
	}

	type PackageResponse struct {
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		Description      string    `json:"description,omitempty"`
		Category         string    `json:"category"`
		Version          string    `json:"version,omitempty"`
		PackageType      string    `json:"package_type"`
		SourceType       string    `json:"source_type"`
		SourceURL        string    `json:"source_url,omitempty"`
		ChecksumSha256   string    `json:"checksum_sha256,omitempty"`
		ExecutionContext string    `json:"execution_context"`
		SilentArgs       string    `json:"silent_args,omitempty"`
		Icon             string    `json:"icon,omitempty"`
		IconURL          string    `json:"icon_url,omitempty"`
		Enabled          bool      `json:"enabled"`
		DownloadURL      string    `json:"download_url"`
		UpdatedAt        time.Time `json:"updated_at"`
	}

	response := make([]PackageResponse, 0, len(pkgs))
	for _, p := range pkgs {
		if !p.Enabled {
			continue
		}
		response = append(response, PackageResponse{
			ID:               p.ID.String(),
			Name:             p.Name,
			Description:      p.Description,
			Category:         p.Category,
			Version:          p.Version,
			PackageType:      p.PackageType.String(),
			SourceType:       p.SourceType.String(),
			SourceURL:        p.SourceURL,
			ChecksumSha256:   p.ChecksumSha256,
			ExecutionContext: p.ExecutionContext.String(),
			SilentArgs:       p.SilentArgs,
			Icon:             p.Icon,
			IconURL:          icons.ResolveIconURL(p.Icon, p.Name),
			Enabled:          p.Enabled,
			DownloadURL:      fmt.Sprintf("/api/v1/packages/download/%s", p.ID.String()),
			UpdatedAt:        p.UpdatedAt,
		})
	}

	return c.JSON(http.StatusOK, response)
}
