package x11input

import (
	"reflect"
	"strings"
	"testing"
)

func TestInternalX11DispatchRejectsInvalidRequestsBeforeBackend(t *testing.T) {
	for _, args := range [][]string{
		{CommandFlag}, {CommandFlag, "up"}, {CommandFlag, "down", "7"},
		{CommandFlag, "down", "256"}, {CommandFlag, "down", "050"},
		{CommandFlag, "up", "50;rm"}, {CommandFlag, "down", "-1"},
		{CommandFlag, "keydown", "50"}, {"--labtether-internal-unknown"},
		append([]string{CommandFlag, "up"}, strings.Fields(strings.Repeat("50 ", MaxKeys+1))...),
	} {
		called := false
		handled, err := Dispatch(args, func(Request) error { called = true; return nil })
		if !handled || err == nil || called {
			t.Fatalf("invalid helper escaped early dispatch: %v, handled=%v err=%v called=%v", args, handled, err, called)
		}
	}
	var got Request
	handled, err := Dispatch([]string{CommandFlag, "up", "50", "62"}, func(request Request) error { got = request; return nil })
	if !handled || err != nil || !reflect.DeepEqual(got, Request{Keys: []byte{50, 62}}) {
		t.Fatalf("valid helper=%v %v %+v", handled, err, got)
	}
	if handled, err := Dispatch([]string{"status"}, func(Request) error { t.Fatal("ordinary command injected input"); return nil }); handled || err != nil {
		t.Fatal("ordinary CLI command claimed by helper")
	}
}

func TestInternalX11CommandHonorsCustomAllowlist(t *testing.T) {
	t.Setenv("LABTETHER_EXEC_ALLOWLIST_MODE", "true")
	t.Setenv("LABTETHER_EXEC_ALLOWED_BINARIES", "xdotool")
	if _, err := NewCommand("down", "50"); err == nil {
		t.Fatal("typed helper bypassed custom command policy")
	}
	t.Setenv("LABTETHER_EXEC_ALLOWED_BINARIES", PolicyName)
	cmd, err := NewCommand("down", "50")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cmd.Args[1:], []string{CommandFlag, "down", "50"}) {
		t.Fatalf("helper args=%v", cmd.Args)
	}
}
