package sessions

import (
	"errors"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestStepUpRenewsAuthTime(t *testing.T) {
	start := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	current := start
	repo := newMemRepo()
	svc := NewServiceWithClock(repo, func() time.Time { return current })
	owner := users.NewID()
	id, session, err := svc.Start(t.Context(), owner, loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}

	current = start.Add(StepUpAfter - time.Microsecond)
	if !svc.AuthRecent(session) {
		t.Fatal("a login just under StepUpAfter is not recent")
	}
	current = start.Add(StepUpAfter)
	if svc.AuthRecent(session) {
		t.Fatal("a login of StepUpAfter ago is recent")
	}

	if _, refused := svc.ConfirmAuth(t.Context(), id, users.NewID()); !errors.Is(refused, ErrNotFound) {
		t.Fatalf("ConfirmAuth() for another user = %v, want ErrNotFound", refused)
	}
	opened, _, err := svc.Open(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.AuthAt.Equal(start) {
		t.Fatalf("auth_at after a refused step-up = %s, want %s", opened.AuthAt, start)
	}

	confirmed, err := svc.ConfirmAuth(t.Context(), id, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !confirmed.AuthAt.Equal(current) || !svc.AuthRecent(confirmed) {
		t.Fatalf("auth_at after the step-up = %s, want %s", confirmed.AuthAt, current)
	}
	opened, _, err = svc.Open(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.AuthAt.Equal(current) {
		t.Fatalf("stored auth_at = %s, want %s", opened.AuthAt, current)
	}
}
