package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestParseConfiguredParentPID(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantPID    int
		configured bool
		wantError  bool
	}{
		{name: "unset", raw: "", configured: false},
		{name: "whitespace", raw: "  ", configured: false},
		{name: "valid", raw: " 4242 ", wantPID: 4242, configured: true},
		{name: "zero", raw: "0", configured: true, wantError: true},
		{name: "negative", raw: "-1", configured: true, wantError: true},
		{name: "text", raw: "parent", configured: true, wantError: true},
		{name: "self", raw: strconv.Itoa(os.Getpid()), configured: true, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pid, configured, err := parseConfiguredParentPID(test.raw)
			if configured != test.configured {
				t.Fatalf("configured = %v, want %v", configured, test.configured)
			}
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %v", err, test.wantError)
			}
			if pid != test.wantPID {
				t.Fatalf("pid = %d, want %d", pid, test.wantPID)
			}
		})
	}
}

func TestContextWithConfiguredParentCancelsWhenParentExits(t *testing.T) {
	original := openParentLifetime
	t.Cleanup(func() { openParentLifetime = original })

	parentDone := make(chan struct{})
	cleanupCalled := false
	openParentLifetime = func(pid int) (<-chan struct{}, func(), error) {
		if pid != 4242 {
			t.Fatalf("pid = %d, want 4242", pid)
		}
		return parentDone, func() { cleanupCalled = true }, nil
	}

	ctx, cleanup, err := contextWithConfiguredParent(context.Background(), "4242")
	if err != nil {
		t.Fatalf("contextWithConfiguredParent: %v", err)
	}
	close(parentDone)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("context was not canceled after parent exit")
	}
	cleanup()
	if !cleanupCalled {
		t.Fatal("parent monitor cleanup was not called")
	}
}

func TestContextWithConfiguredParentFailsClosedWhenMonitorCannotOpen(t *testing.T) {
	original := openParentLifetime
	t.Cleanup(func() { openParentLifetime = original })
	openParentLifetime = func(int) (<-chan struct{}, func(), error) {
		return nil, nil, errors.New("parent unavailable")
	}

	ctx, cleanup, err := contextWithConfiguredParent(context.Background(), "4242")
	if err == nil || ctx != nil || cleanup != nil {
		t.Fatalf(
			"ctxNil=%v cleanupNil=%v err=%v, want fail-closed error",
			ctx == nil,
			cleanup == nil,
			err,
		)
	}
}
