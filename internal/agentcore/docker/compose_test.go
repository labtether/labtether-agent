package docker

import (
	"reflect"
	"testing"
)

func TestDockerComposeBuildCommand(t *testing.T) {
	selected := composeSelection{Name: "custom_project", Dir: "/work/sibling-dir", Files: []string{"/outside/first.yml", "/work/sibling-dir/ second.yml "}}
	for _, version := range []int{1, 2} {
		name, args := composeCommandArgs(version, "tcp://localhost:8123/engine", selected, "up", "-d")
		want := []string{"--host", "tcp://localhost:8123/engine"}
		if version == 2 {
			want = append(want, "compose")
			if name != "docker" {
				t.Fatal(name)
			}
		} else if name != "docker-compose" {
			t.Fatal(name)
		}
		want = append(want, "--project-directory", selected.Dir, "-p", selected.Name, "-f", selected.Files[0], "-f", selected.Files[1], "up", "-d")
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("version%d args=%q want%q", version, args, want)
		}
	}
}
