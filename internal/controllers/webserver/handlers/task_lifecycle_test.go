package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestTaskLifecycleTimeoutFormValidation(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    int
		invalid bool
	}{
		{"", 0, false}, {"0", 0, false}, {"1", 1, false}, {"120", 120, false}, {"-1", 0, true}, {"1.5", 0, true}, {"abc", 0, true}, {"99999999999999999999999", 0, true},
	} {
		t.Run("timeout_"+tc.value, func(t *testing.T) {
			form := url.Values{"task-agent-type": {"windows"}, "task-description": {"fixture"}, "powershell-script": {"Write-Output fixture"}, "task-type": {"powershell_type"}, "powershell-run": {"once"}, "task-timeout": {tc.value}}
			r := httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(form.Encode()))
			r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			cfg, err := validateTaskForm(echo.New().NewContext(r, httptest.NewRecorder()))
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid timeout accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Timeout != tc.want {
				t.Fatalf("got timeout %d want %d", cfg.Timeout, tc.want)
			}
		})
	}
}
