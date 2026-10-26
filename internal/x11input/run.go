package x11input

import (
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"runtime"
	"strconv"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

var localDisplay = regexp.MustCompile(`^:([0-9]{1,5})(?:\.([0-9]{1,5}))?$`)

// Run is used only in the subprocess. The parent owns its hard deadline and
// kill/reap, including a stalled X server handshake, write or acknowledgement.
// XGB speaks XTEST directly: no implicit modifier or XKB group changes occur.
func Run(request Request) error {
	if len(request.Keys) == 0 || len(request.Keys) > MaxKeys {
		return fmt.Errorf("invalid X11 helper key count")
	}
	for _, code := range request.Keys {
		if code < 8 {
			return fmt.Errorf("invalid X11 physical keycode")
		}
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("X11 input helper is available only on Linux")
	}
	parts := localDisplay.FindStringSubmatch(os.Getenv("DISPLAY"))
	if parts == nil {
		return fmt.Errorf("X11 helper requires an explicit local display")
	}
	number, _ := strconv.Atoi(parts[1])
	display := ":" + strconv.Itoa(number)
	if parts[2] != "" {
		screen, _ := strconv.Atoi(parts[2])
		display += "." + strconv.Itoa(screen)
	}
	// This function runs only in the child. XGB logs authority lookup errors;
	// keep private authority paths and server-provided errors out of output.
	xgb.Logger = log.New(io.Discard, "", 0)
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		return fmt.Errorf("cannot connect or authenticate to X11 input display")
	}
	defer conn.Close()
	if err := xtest.Init(conn); err != nil {
		return fmt.Errorf("XTEST input extension is unavailable")
	}
	return sendKeys(conn, request)
}

func sendKeys(conn *xgb.Conn, request Request) error {
	typeCode := byte(xproto.KeyRelease)
	if request.Press {
		typeCode = xproto.KeyPress
	}
	checks := make([]xtest.FakeInputCookie, 0, len(request.Keys))
	for _, code := range request.Keys {
		checks = append(checks, xtest.FakeInputChecked(conn, typeCode, code, 0, 0, 0, 0, 0))
	}
	for _, check := range checks {
		if err := check.Check(); err != nil {
			return fmt.Errorf("XTEST key event: %w", err)
		}
	}
	return nil
}
