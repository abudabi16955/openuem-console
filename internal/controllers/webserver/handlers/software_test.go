package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSoftwareFilters(t *testing.T) {
	e := echo.New()
	h := &Handler{}

	t.Run("parses filterBySearch and specific filters from form values", func(t *testing.T) {
		form := url.Values{
			"filterBySearch":       {"chrome"},
			"filterByAppName":      {"Google Chrome"},
			"filterByAppPublisher": {"Google LLC"},
			"filterByAppVersion":   {"120.0"},
		}
		req := httptest.NewRequest(http.MethodPost, "/software/inventory", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		f, err := h.GetSoftwareFilters(c)
		require.NoError(t, err)
		assert.Equal(t, "chrome", f.Search)
		assert.Equal(t, "Google Chrome", f.AppName)
		assert.Equal(t, "Google LLC", f.Vendor)
		assert.Equal(t, "120.0", f.Version)
	})

	t.Run("parses filterBySearch from query parameters", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/software/inventory?filterBySearch=firefox", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		f, err := h.GetSoftwareFilters(c)
		require.NoError(t, err)
		assert.Equal(t, "firefox", f.Search)
	})

	t.Run("empty filters when no query or form parameters provided", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/software/inventory", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		f, err := h.GetSoftwareFilters(c)
		require.NoError(t, err)
		assert.Empty(t, f.Search)
		assert.Empty(t, f.AppName)
		assert.Empty(t, f.Vendor)
		assert.Empty(t, f.Version)
	})
}
