package remoteaccess

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestWebRTCScaledCaptureMapsInputBackToRootScreen(t *testing.T) {
	original := NewWebRTCSecurityCommand
	t.Cleanup(func() { NewWebRTCSecurityCommand = original })
	var got []string
	NewWebRTCSecurityCommand = func(name string, args ...string) (*exec.Cmd, error) {
		if name != "xdotool" {
			t.Fatalf("unexpected command %q", name)
		}
		got = append([]string(nil), args...)
		return exec.Command(os.Args[0], "-test.run=^$"), nil
	}
	// The center of a 1920x1080 encoded frame must hit the center of the
	// 3840x2160 root screen, even when the browser also scales its video.
	sess := &WebRTCSession{inputGeometry: webRTCCaptureGeometry{
		sourceWidth: 3840, sourceHeight: 2160, videoWidth: 1920, videoHeight: 1080,
	}}
	for _, tc := range []struct{ display, screen string }{
		{":0", "0"}, {":0.1", "1"}, {":12.3", "3"}, {":2", "0"}, {"monitor.1", "0"},
	} {
		if err := InjectSingleInput(WebRTCInputEvent{Type: "mousemove", X: 960, Y: 540}, tc.display, "", sess); err != nil {
			t.Fatal(err)
		}
		want := []string{"mousemove", "--screen", tc.screen, "1920", "1080"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("display %q input command=%v, want %v", tc.display, got, want)
		}
	}
}

func TestWebRTCCaptureFitsRootAspectRatioWithoutHiddenBorders(t *testing.T) {
	for _, tc := range []struct {
		name                                             string
		sourceWidth, sourceHeight, wantWidth, wantHeight int
	}{
		{"wide root", 5760, 2160, 1920, 720},
		{"portrait root", 1080, 1920, 606, 1080},
		{"standard root", 3840, 2160, 1920, 1080},
	} {
		t.Run(tc.name, func(t *testing.T) {
			width, height := fitWebRTCVideoSize(tc.sourceWidth, tc.sourceHeight, 1920, 1080)
			if width != tc.wantWidth || height != tc.wantHeight {
				t.Fatalf("encoded size=%dx%d, want %dx%d", width, height, tc.wantWidth, tc.wantHeight)
			}
			geometry := webRTCCaptureGeometry{sourceWidth: tc.sourceWidth, sourceHeight: tc.sourceHeight, videoWidth: width, videoHeight: height}
			mapped := geometry.mapInput(WebRTCInputEvent{X: width / 2, Y: height / 2})
			if mapped.X != tc.sourceWidth/2 || mapped.Y != tc.sourceHeight/2 {
				t.Fatalf("encoded center missed root center: %+v", mapped)
			}
		})
	}
	pipeline := BuildGStreamerVideoPipeline(GstPipelineConfig{display: ":0", width: 1920, height: 720, encoder: "x264enc"})
	for _, required := range []string{"videoscale add-borders=false", "width=1920,height=720,pixel-aspect-ratio=1/1"} {
		if !strings.Contains(pipeline, required) {
			t.Fatalf("pipeline does not preserve full-frame input mapping: %s", pipeline)
		}
	}
}

func TestWebRTCCaptureGeometryUsesFullRootNotFirstMonitor(t *testing.T) {
	width, height, err := parseWebRTCCaptureGeometry("Screen 0: minimum 8 x 8, current 5760 x 2160, maximum 32767 x 32767\nDP-1 connected primary 1920x1080+0+0\n")
	if err != nil || width != 5760 || height != 2160 {
		t.Fatalf("geometry=%dx%d %v", width, height, err)
	}
	for _, invalid := range []string{"DP-1 connected 1920x1080+0+0", "current 0 x 1080", "current 99999999999999999999999 x 1080"} {
		if _, _, err := parseWebRTCCaptureGeometry(invalid); err == nil {
			t.Fatalf("accepted geometry %q", invalid)
		}
	}
}

func TestWebRTCCaptureMappingClampsAndPreservesUnknownGeometry(t *testing.T) {
	geometry := webRTCCaptureGeometry{sourceWidth: 3840, sourceHeight: 2160, videoWidth: 1920, videoHeight: 1080}
	mapped := geometry.mapInput(WebRTCInputEvent{Type: "mousemove", X: -12, Y: 10000})
	if mapped.X != 0 || mapped.Y != 2159 {
		t.Fatalf("out-of-bounds mapping=%+v", mapped)
	}
	original := WebRTCInputEvent{Type: "mousemove", X: 112, Y: 74}
	if got := (webRTCCaptureGeometry{}).mapInput(original); got != original {
		t.Fatal("unknown source geometry was guessed")
	}
}

func TestWebRTCCaptureMappingReachesBothEdges(t *testing.T) {
	for _, tc := range []struct{ source, encoded int }{
		{3840, 1920}, {1080, 606}, {1920, 1920}, {640, 1920}, {1, 2}, {32, 1},
	} {
		geometry := webRTCCaptureGeometry{sourceWidth: tc.source, sourceHeight: tc.source,
			videoWidth: tc.encoded, videoHeight: tc.encoded}
		for _, value := range []int{-1, 0, tc.encoded - 1, tc.encoded + 10} {
			want := 0
			if value >= tc.encoded-1 && tc.encoded > 1 {
				want = tc.source - 1
			}
			got := geometry.mapInput(WebRTCInputEvent{X: value, Y: value})
			if got.X != want || got.Y != want {
				t.Fatalf("source=%d encoded=%d value=%d mapped=%+v want=%d", tc.source, tc.encoded, value, got, want)
			}
		}
		if tc.source == tc.encoded {
			for _, value := range []int{1, 123, 960} {
				got := geometry.mapInput(WebRTCInputEvent{X: value, Y: value})
				if got.X != value || got.Y != value {
					t.Fatalf("1:1 mapping changed pixel %d to %+v", value, got)
				}
			}
		}
	}
}
