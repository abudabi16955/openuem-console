package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"os"
	"path/filepath"
	"context"
	"testing"
	"github.com/invopop/ctxi18n"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/open-uem/ent/enttest"
	"github.com/open-uem/ent/selfservicepackage"
	"github.com/open-uem/openuem-console/internal/icons"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func initLocalesForTest(t *testing.T) context.Context {
	t.Helper()
	_ = ctxi18n.LoadWithDefault(locales.Content, "en")
	ctx, _ := ctxi18n.WithLocale(context.Background(), "en")
	return ctx
}

func generateTestCert(t *testing.T) (*x509.Certificate, string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "agent-test",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString(certDER)
	return parsedCert, encoded
}

func TestPackages_DownloadAuth(t *testing.T) {
	e := echo.New()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	model := &models.Model{Client: client}
	h := &Handler{
		Model: model,
	}

	t.Run("unauthorized without session or cert", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/download/"+uuid.New().String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(uuid.New().String())

		err := h.DownloadPackage(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, he.Code)
	})

	t.Run("authorized with TLS peer certificate", func(t *testing.T) {
		cert, _ := generateTestCert(t)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/download/"+uuid.New().String(), nil)
		req.TLS = cryptoTLSStub(cert)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(uuid.New().String())

		err := h.DownloadPackage(c)
		// Should pass auth and fail with 404 Not Found since package doesn't exist
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusNotFound, he.Code)
	})

	t.Run("authorized with Client-Cert header", func(t *testing.T) {
		_, encodedCert := generateTestCert(t)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/download/"+uuid.New().String(), nil)
		req.Header.Set("Client-Cert", encodedCert)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(uuid.New().String())

		err := h.DownloadPackage(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusNotFound, he.Code)
	})
}

func cryptoTLSStub(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
}

func TestPackages_DownloadPackageContent(t *testing.T) {
	e := echo.New()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	model := &models.Model{Client: client}
	h := &Handler{
		Model: model,
	}

	cert, _ := generateTestCert(t)

	// Create a dummy package file
	tmpDir := t.TempDir()
	dummyFile := filepath.Join(tmpDir, "installer.msi")
	content := []byte("fake-msi-package-binary-data")
	err := os.WriteFile(dummyFile, content, 0644)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(content)
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	// Create package in DB
	pkg, err := model.CreateSelfServicePackage(
		t.Context(),
		"Test Package",
		"Description",
		"General",
		"1.0.0",
		selfservicepackage.PackageTypeMsi,
		selfservicepackage.SourceTypeUpload,
		"",
		dummyFile,
		expectedHash,
		selfservicepackage.ExecutionContextSystem,
		"/qn",
		"icon",
		true,
	)
	require.NoError(t, err)

	// Request download
	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/download/"+pkg.ID.String(), nil)
	req.TLS = cryptoTLSStub(cert)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(pkg.ID.String())

	err = h.DownloadPackage(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, expectedHash, rec.Header().Get("X-Checksum-SHA256"))
	assert.Equal(t, content, rec.Body.Bytes())
}

func TestPackages_DownloadHTTPSRedirect(t *testing.T) {
	e := echo.New()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	model := &models.Model{Client: client}
	h := &Handler{
		Model: model,
	}

	cert, _ := generateTestCert(t)

	pkg, err := model.CreateSelfServicePackage(
		t.Context(),
		"HTTPS Package",
		"Description",
		"General",
		"2.0.0",
		selfservicepackage.PackageTypeExe,
		selfservicepackage.SourceTypeHTTPS,
		"https://example.com/downloads/setup.exe",
		"",
		"",
		selfservicepackage.ExecutionContextUser,
		"/silent",
		"icon",
		true,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/download/"+pkg.ID.String(), nil)
	req.TLS = cryptoTLSStub(cert)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(pkg.ID.String())

	err = h.DownloadPackage(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "https://example.com/downloads/setup.exe", rec.Header().Get("Location"))
}

func TestPackages_APIGetPackages(t *testing.T) {
	e := echo.New()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	model := &models.Model{Client: client}
	h := &Handler{
		Model: model,
	}

	cert, _ := generateTestCert(t)

	_, err := model.CreateSelfServicePackage(
		t.Context(),
		"Package 1",
		"Description 1",
		"General",
		"1.0.0",
		selfservicepackage.PackageTypeMsi,
		selfservicepackage.SourceTypeUpload,
		"",
		"/file.msi",
		"hash1",
		selfservicepackage.ExecutionContextSystem,
		"",
		"",
		true,
	)
	require.NoError(t, err)

	_, err = model.CreateSelfServicePackage(
		t.Context(),
		"Mozilla Firefox",
		"Firefox Browser",
		"General",
		"120.0",
		selfservicepackage.PackageTypeExe,
		selfservicepackage.SourceTypeUpload,
		"",
		"/firefox.exe",
		"hash_firefox",
		selfservicepackage.ExecutionContextSystem,
		"",
		"firefox",
		true,
	)
	require.NoError(t, err)

	_, err = model.CreateSelfServicePackage(
		t.Context(),
		"Package Disabled",
		"Description 2",
		"General",
		"1.0.0",
		selfservicepackage.PackageTypeMsi,
		selfservicepackage.SourceTypeUpload,
		"",
		"/file2.msi",
		"hash2",
		selfservicepackage.ExecutionContextSystem,
		"",
		"",
		false,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages", nil)
	req.TLS = cryptoTLSStub(cert)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = h.APIGetPackages(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Package 1")
	assert.Contains(t, rec.Body.String(), "data:image/svg+xml;base64,")
	assert.NotContains(t, rec.Body.String(), "Package Disabled")
}

func TestPackages_SaveUploadAndValidation(t *testing.T) {
	e := echo.New()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	tmpDir := t.TempDir()
	model := &models.Model{Client: client}
	defaultTenant, err := client.Tenant.Create().SetDescription("DefaultTenant").SetIsDefault(true).Save(t.Context())
	require.NoError(t, err)
	_, err = client.Site.Create().SetDescription("DefaultSite").SetIsDefault(true).SetTenantID(defaultTenant.ID).Save(t.Context())
	require.NoError(t, err)

	_, err = client.Settings.Create().SetTenant(defaultTenant).Save(t.Context())
	require.NoError(t, err)

	_, err = client.Settings.Create().Save(t.Context())
	require.NoError(t, err)

	_ = os.WriteFile(filepath.Join(tmpDir, "latest.json"), []byte("{\"version\": \"1.0.0\"}"), 0644)
	h := &Handler{
		Model:                model,
		DownloadDir:          filepath.Join(tmpDir, "downloads"),
		ServerReleasesFolder: tmpDir,
	}

	t.Run("invalid package type", func(t *testing.T) {
		form := url.Values{
			"name":         {"Test"},
			"package_type": {"invalid_type"},
		}
		req := httptest.NewRequest(http.MethodPost, "/packages/new", strings.NewReader(form.Encode())).WithContext(initLocalesForTest(t))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("csrf", "test-csrf")

		err := h.SavePackage(c)
		assert.NoError(t, err)
		assert.Contains(t, rec.Body.String(), "Invalid package type")
		assert.Equal(t, "#new-package-error", rec.Header().Get("HX-Retarget"))
		assert.Equal(t, "innerHTML", rec.Header().Get("HX-Reswap"))
	})

	t.Run("missing package name", func(t *testing.T) {
		form := url.Values{
			"name": {"   "},
		}
		req := httptest.NewRequest(http.MethodPost, "/packages/new", strings.NewReader(form.Encode())).WithContext(initLocalesForTest(t))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("csrf", "test-csrf")

		err := h.SavePackage(c)
		assert.NoError(t, err)
		assert.Contains(t, rec.Body.String(), "Package name is required")
	})

	t.Run("valid https package creation", func(t *testing.T) {
		form := url.Values{
			"name":              {"Google Chrome"},
			"package_type":      {"msi"},
			"source_type":        {"https"},
			"source_url":         {"https://example.com/app.msi"},
			"execution_context":  {"system"},
			"enabled":            {"true"},
			"icon":               {"chrome"},
		}
		req := httptest.NewRequest(http.MethodPost, "/packages/new", strings.NewReader(form.Encode())).WithContext(initLocalesForTest(t))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("csrf", "test-csrf")

		err := h.SavePackage(c)
		assert.NoError(t, err)
		assert.Contains(t, rec.Header().Get("HX-Redirect"), "/software")

		all, err := model.GetAllSelfServicePackages(t.Context())
		require.NoError(t, err)
		assert.Len(t, all, 1)
		assert.Equal(t, "Google Chrome", all[0].Name)
		assert.True(t, strings.HasPrefix(all[0].Icon, "data:image/svg+xml;base64,"))
	})


	t.Run("update package validation error and retarget", func(t *testing.T) {
		all, err := model.GetAllSelfServicePackages(t.Context())
		require.NoError(t, err)
		require.Len(t, all, 1)
		pkg := all[0]

		form := url.Values{
			"name":         {""},
			"package_type": {"msi"},
		}
		req := httptest.NewRequest(http.MethodPost, "/packages/edit/"+pkg.ID.String(), strings.NewReader(form.Encode())).WithContext(initLocalesForTest(t))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(pkg.ID.String())
		c.Set("csrf", "test-csrf")

		err = h.UpdatePackage(c)
		assert.NoError(t, err)
		assert.Contains(t, rec.Body.String(), "Package name is required")
		assert.Contains(t, rec.Header().Get("HX-Retarget"), "edit-package-error")
		assert.Equal(t, "innerHTML", rec.Header().Get("HX-Reswap"))
	})

	t.Run("delete package", func(t *testing.T) {
		all, err := model.GetAllSelfServicePackages(t.Context())
		require.NoError(t, err)
		require.Len(t, all, 1)

		req := httptest.NewRequest(http.MethodDelete, "/packages/"+all[0].ID.String(), nil).WithContext(initLocalesForTest(t))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(all[0].ID.String())
		c.Set("csrf", "test-csrf")

		err = h.DeletePackage(c)
		assert.NoError(t, err)
		assert.Contains(t, rec.Header().Get("HX-Redirect"), "/software")

		remaining, err := model.GetAllSelfServicePackages(t.Context())
		require.NoError(t, err)
		assert.Empty(t, remaining)
	})
}

func TestPackages_CustomIconPersistenceAndPriority(t *testing.T) {
	e := echo.New()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	model := &models.Model{Client: client}
	h := &Handler{
		Model: model,
	}

	cert, _ := generateTestCert(t)

	// Custom user uploaded icon for a package named "Mozilla Firefox"
	customPNG := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

	ffPkg, err := model.CreateSelfServicePackage(
		t.Context(),
		"Mozilla Firefox",
		"Customized Firefox",
		"Browsers",
		"133.0",
		selfservicepackage.PackageTypeExe,
		selfservicepackage.SourceTypeUpload,
		"",
		"/firefox.exe",
		"hash_firefox_custom",
		selfservicepackage.ExecutionContextSystem,
		"",
		customPNG,
		true,
	)
	require.NoError(t, err)

	// Verify DB initially has custom icon
	dbPkg, err := model.GetSelfServicePackageByID(t.Context(), ffPkg.ID)
	require.NoError(t, err)
	assert.Equal(t, customPNG, dbPkg.Icon)

	// 1. Call APIGetPackages
	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages", nil)
	req.TLS = cryptoTLSStub(cert)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = h.APIGetPackages(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify response body retains user's exact custom icon (not overwritten by brand fallback)
	resBody := rec.Body.String()
	assert.Contains(t, resBody, customPNG)

	// Verify DB record was NOT mutated / overwritten
	dbPkgAfter, err := model.GetSelfServicePackageByID(t.Context(), ffPkg.ID)
	require.NoError(t, err)
	assert.Equal(t, customPNG, dbPkgAfter.Icon, "Custom uploaded icon must remain untouched in DB across APIGetPackages listing")
}

func TestPackages_BrandFallbackWithoutUpload(t *testing.T) {
	e := echo.New()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	model := &models.Model{Client: client}
	h := &Handler{
		Model: model,
	}

	cert, _ := generateTestCert(t)

	// Package named "Mozilla Firefox" created without an uploaded custom icon
	ffPkg, err := model.CreateSelfServicePackage(
		t.Context(),
		"Mozilla Firefox",
		"Official Winget Package",
		"Browsers",
		"133.0",
		selfservicepackage.PackageTypeWinget,
		selfservicepackage.SourceTypeHTTPS,
		"Mozilla.Firefox",
		"",
		"",
		selfservicepackage.ExecutionContextSystem,
		"",
		"",
		true,
	)
	require.NoError(t, err)

	// Call APIGetPackages
	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages", nil)
	req.TLS = cryptoTLSStub(cert)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = h.APIGetPackages(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Response should resolve to official full-color Firefox SVG
	expectedBrandIcon := icons.GetBrandIcon("firefox")
	require.NotEmpty(t, expectedBrandIcon)
	resBody := rec.Body.String()
	assert.Contains(t, resBody, expectedBrandIcon, "APIGetPackages should return official brand icon fallback for Mozilla Firefox")

	// Verify DB record was not destructively mutated
	dbPkgAfter, err := model.GetSelfServicePackageByID(t.Context(), ffPkg.ID)
	require.NoError(t, err)
	assert.Equal(t, "", dbPkgAfter.Icon, "Database icon field should remain empty when not set by user")
}
