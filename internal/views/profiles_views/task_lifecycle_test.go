package profiles_views

import (
	"bytes"
	"context"
	"github.com/invopop/ctxi18n"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"strings"
	"testing"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/taskreport"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestTaskLifecycleCounters(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report ent.TaskReport
		want   [5]int
	}{
		{"pending", ent.TaskReport{Status: taskreport.StatusPending}, [5]int{1, 0, 0, 0, 0}},
		{"running", ent.TaskReport{Status: taskreport.StatusRunning, StartedAt: "start"}, [5]int{0, 1, 0, 0, 0}},
		{"completed", ent.TaskReport{Status: taskreport.StatusCompleted, StartedAt: "start", End: "end"}, [5]int{0, 0, 1, 0, 0}},
		{"failed", ent.TaskReport{Status: taskreport.StatusFailed, Failed: true}, [5]int{0, 0, 0, 1, 0}},
		{"timeout", ent.TaskReport{Status: taskreport.StatusFailed, Failed: true, Timeout: true}, [5]int{0, 0, 0, 0, 1}},
		{"retry_with_previous_timeout", ent.TaskReport{Status: taskreport.StatusRunning, StartedAt: "new", End: "old", Failed: true, Timeout: true}, [5]int{0, 1, 0, 0, 0}},
		{"completed_without_timestamps", ent.TaskReport{Status: taskreport.StatusCompleted}, [5]int{0, 0, 1, 0, 0}},
		{"legacy_completed_default_pending", ent.TaskReport{Status: taskreport.StatusPending, End: "legacy end"}, [5]int{0, 0, 1, 0, 0}},
		{"legacy_failed_default_pending", ent.TaskReport{Status: taskreport.StatusPending, Failed: true, End: "legacy end"}, [5]int{0, 0, 0, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.report.Edges.Task = &ent.Task{}
			r := []*ent.TaskReport{&tc.report}
			got := [5]int{getPendingTasks(r), getRunningTasks(r), getSuccessfulTasks(r), getFailedTasks(r), getTimeoutTasks(r)}
			if got != tc.want {
				t.Fatalf("pending/running/completed/failed/timeout = %v, want %v", got, tc.want)
			}
			tc.report.Edges.Task.Disabled = true
			if getPendingTasks(r)+getRunningTasks(r)+getSuccessfulTasks(r)+getFailedTasks(r)+getTimeoutTasks(r) != 0 {
				t.Fatal("disabled task counted")
			}
		})
	}
}

func TestTaskLifecycleReportDetailEscapesLogs(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	r := &ent.TaskReport{Status: taskreport.StatusFailed, Timeout: true, Failed: true, StdOutput: "stdout <script>alert(1)</script>", StdError: "stderr <b>fixture</b>"}
	r.Edges.Task = &ent.Task{Name: "fixture"}
	issue := &ent.ProfileIssue{}
	issue.Edges.Tasksreports = []*ent.TaskReport{r}
	var b bytes.Buffer
	if err := ReportDetail(issue, &partials.CommonInfo{}, 0).Render(ctx, &b); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{i18n.T(ctx, "tasks.status.timeout"), "stdout &lt;script&gt;", "stderr &lt;b&gt;"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in rendered detail", want)
		}
	}
	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Fatal("unescaped log")
	}
}
