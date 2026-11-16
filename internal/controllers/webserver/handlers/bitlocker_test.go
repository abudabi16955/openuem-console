package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestRevealBitLockerKey_Validation(t *testing.T) {
	e := echo.New()
	h := &Handler{}

	t.Run("missing uuid", func(t *testing.T) {
		form := url.Values{"key_id": {"test-key"}, "reason": {"valid reason"}}
		req := httptest.NewRequest(http.MethodPost, "/computers//bitlocker/reveal", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("uuid")
		c.SetParamValues("")

		err := h.RevealBitLockerKey(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, he.Code)
		assert.Contains(t, he.Message, "missing uuid")
	})

	t.Run("missing key_id", func(t *testing.T) {
		form := url.Values{"reason": {"valid reason"}}
		req := httptest.NewRequest(http.MethodPost, "/computers/test-agent/bitlocker/reveal", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("uuid")
		c.SetParamValues("test-agent")

		err := h.RevealBitLockerKey(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, he.Code)
		assert.Contains(t, he.Message, "missing key_id")
	})

	t.Run("reason too short", func(t *testing.T) {
		shortReasons := []string{"", "   ", "a", "ab", "abc", "abcd", "  ab "}
		for _, r := range shortReasons {
			form := url.Values{"key_id": {"test-key"}, "reason": {r}}
			req := httptest.NewRequest(http.MethodPost, "/computers/test-agent/bitlocker/reveal", strings.NewReader(form.Encode()))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("uuid")
			c.SetParamValues("test-agent")

			err := h.RevealBitLockerKey(c)
			assert.Error(t, err)
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusBadRequest, he.Code)
			assert.Contains(t, he.Message, "reason must be at least 5 characters long")
		}
	})
}

func TestForceBitLockerEscrow_Validation(t *testing.T) {
	e := echo.New()
	h := &Handler{}

	t.Run("missing uuid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/computers//bitlocker/force-escrow", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("uuid")
		c.SetParamValues("")

		err := h.ForceBitLockerEscrow(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, he.Code)
	})

	t.Run("nats not connected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/computers/test-agent/bitlocker/force-escrow", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("uuid")
		c.SetParamValues("test-agent")

		err := h.ForceBitLockerEscrow(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusInternalServerError, he.Code)
		assert.Contains(t, he.Message, "NATS connection is not available")
	})
}
