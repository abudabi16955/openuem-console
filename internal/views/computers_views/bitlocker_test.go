package computers_views

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/invopop/ctxi18n"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func initLocales(t *testing.T) context.Context {
	t.Helper()
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestBitLockerKeyRevealed_UnifiedMonospaceAndGap(t *testing.T) {
	ctx := initLocales(t)
	var b bytes.Buffer
	pwd := "111111-222222-333333-444444-555555-666666-777777-888888"
	if err := BitLockerKeyRevealed("{KEY-123}", pwd).Render(ctx, &b); err != nil {
		t.Fatalf("failed to render BitLockerKeyRevealed: %v", err)
	}
	s := b.String()

	expectedClass := "px-3 py-1.5 text-xs font-mono font-bold tracking-wider bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-800 dark:text-slate-100 select-all shadow-sm"
	if !strings.Contains(s, expectedClass) {
		t.Errorf("missing unified monospace class %q in rendered output:\n%s", expectedClass, s)
	}

	if !strings.Contains(s, pwd) {
		t.Errorf("expected full password %q to be present in output:\n%s", pwd, s)
	}

	if !strings.Contains(s, "flex items-center gap-2 ml-1 text-xs") {
		t.Errorf("expected copy button to have gap-2, got:\n%s", s)
	}
}

func TestBitLockerRevealModal_HxOnAndDarkModeContrast(t *testing.T) {
	ctx := initLocales(t)
	key := &ent.BitlockerKey{
		KeyID:       "{TEST-KEY-ID-123}",
		DriveLetter: "C:",
	}
	modalID := "modal-reveal-" + SafeKeyID(key.KeyID)
	revealURL := "/computers/agent-123/bitlocker/reveal"

	var b bytes.Buffer
	if err := BitLockerRevealModal(key, revealURL, modalID).Render(ctx, &b); err != nil {
		t.Fatalf("failed to render BitLockerRevealModal: %v", err)
	}
	s := b.String()

	expectedHxOn := `hx-on::after-request="if (event.detail.successful) UIkit.modal(&#39;#` + modalID + `&#39;).hide()"`
	if !strings.Contains(s, expectedHxOn) && !strings.Contains(s, `UIkit.modal('#`+modalID+`').hide()`) {
		t.Errorf("expected modal closing via hx-on::after-request, got:\n%s", s)
	}

	expectedDriveKeyContrast := "text-slate-800 dark:text-slate-100"
	if !strings.Contains(s, expectedDriveKeyContrast) {
		t.Errorf("expected drive & key ID to have explicit text contrast %q, got:\n%s", expectedDriveKeyContrast, s)
	}

	expectedReasonLabel := `class="text-xs font-semibold uppercase tracking-wider text-muted-foreground"`
	if !strings.Contains(s, expectedReasonLabel) {
		t.Errorf("expected Reason label to have %q, got:\n%s", expectedReasonLabel, s)
	}
}

func TestBitLockerSection_BadgesSpacingAndEscrowGap(t *testing.T) {
	ctx := initLocales(t)
	agent := &ent.Agent{
		ID: "agent-test-uuid",
	}
	commonInfo := &partials.CommonInfo{}

	now := time.Now()
	keys := []*ent.BitlockerKey{
		{
			KeyID:       "{ACTIVE-KEY-1}",
			DriveLetter: "C:",
			IsActive:    true,
			CreatedAt:   now,
		},
		{
			KeyID:       "{ROTATED-KEY-2}",
			DriveLetter: "C:",
			IsActive:    false,
			CreatedAt:   now.Add(-24 * time.Hour),
		},
	}

	var b bytes.Buffer
	if err := BitLockerSection(nil, agent, keys, commonInfo).Render(ctx, &b); err != nil {
		t.Fatalf("failed to render BitLockerSection: %v", err)
	}
	s := b.String()

	// 1. Force escrow button gap-2
	if !strings.Contains(s, "flex items-center gap-2 text-xs") {
		t.Errorf("expected Force Escrow button to have gap-2, got:\n%s", s)
	}

	// 2. Active keys header mt-4
	if !strings.Contains(s, `class="text-sm font-semibold mt-4 mb-3 flex items-center gap-2"`) {
		t.Errorf("expected Active Recovery Keys header to have mt-4 mb-3, got:\n%s", s)
	}

	// 3. Active badge
	if !strings.Contains(s, "bg-green-600 text-white text-xs px-2 py-0.5 rounded") {
		t.Errorf("expected Active badge to use bg-green-600 text-white, got:\n%s", s)
	}

	// 4. Rotated badge
	if !strings.Contains(s, "uk-badge uk-badge-secondary text-xs px-2 py-0.5 rounded") {
		t.Errorf("expected Rotated badge to use uk-badge-secondary, got:\n%s", s)
	}

	// 5. Empty state mt-4 mb-4
	var bEmpty bytes.Buffer
	if err := BitLockerSection(nil, agent, nil, commonInfo).Render(ctx, &bEmpty); err != nil {
		t.Fatalf("failed to render empty BitLockerSection: %v", err)
	}
	sEmpty := bEmpty.String()
	if !strings.Contains(sEmpty, `class="uk-text-small uk-text-muted mt-4 mb-4"`) {
		t.Errorf("expected empty state to have mt-4 mb-4, got:\n%s", sEmpty)
	}
}
