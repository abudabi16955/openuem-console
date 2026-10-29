package tasks_views

import (
	"bytes"
	"context"
	"github.com/PuerkitoBio/goquery"
	"github.com/alexedwards/scs/v2"
	"github.com/invopop/ctxi18n"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/ent/taskreport"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTaskLifecycleStatusBadges(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		status          string
		failed, timeout bool
		want            string
	}{
		{"pending", false, false, "pending"}, {"running", false, false, "running"}, {"completed", false, false, "completed"}, {"failed", true, false, "failed"}, {"failed", true, true, "timeout"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			var b bytes.Buffer
			if err := TaskStatusBadge(tc.status, tc.failed, tc.timeout).Render(ctx, &b); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(b.String(), i18n.T(ctx, "tasks.status."+tc.want)) || strings.Contains(b.String(), "MISSING") {
				t.Fatalf("unexpected badge: %s", b.String())
			}
		})
	}
}

func TestTaskLifecycleEditFormAndEndpointLogs(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tasks/73", nil).WithContext(ctx), httptest.NewRecorder())
	ci := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "-1", SiteID: "-1", IsTask: true}
	task := &ent.Task{ID: 73, Name: "fixture", Timeout: 120, Type: task.TypePowershellScript, AgentType: task.AgentTypeWindows}
	var reports []*ent.TaskReport
	for _, state := range []taskreport.Status{taskreport.StatusPending, taskreport.StatusRunning, taskreport.StatusCompleted, taskreport.StatusFailed} {
		reports = append(reports, &ent.TaskReport{Status: state, StdOutput: "stdout <script>fixture</script>", StdError: "stderr fixture"})
	}
	reports = append(reports, &ent.TaskReport{Status: taskreport.StatusFailed, Failed: true, Timeout: true})
	var b bytes.Buffer
	if err := EditTask(c, 42, task, reports, ci).Render(ctx, &b); err != nil {
		t.Fatal(err)
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	input := doc.Find("input[name='task-timeout']")
	if input.Length() != 1 || input.AttrOr("value", "") != "120" || input.AttrOr("min", "") != "0" {
		t.Fatal("timeout input missing or not prefilled")
	}
	if doc.Find("tbody tr").Length() != 5 {
		t.Fatal("expected five endpoint rows")
	}
	for _, status := range []string{"pending", "running", "completed", "failed", "timeout"} {
		if !strings.Contains(doc.Text(), i18n.T(ctx, "tasks.status."+status)) {
			t.Errorf("missing status %s", status)
		}
	}
	if !strings.Contains(b.String(), "stdout &lt;script&gt;fixture&lt;/script&gt;") || !strings.Contains(b.String(), "stderr fixture") {
		t.Fatal("endpoint logs absent or unescaped")
	}
}
