package system

import "testing"

func TestParseMountsDFOutputDarwinPOSIX(t *testing.T) {
	t.Parallel()

	out := `Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/disk3s1s1   239362496  12274844  25870940    33%    /
/dev/disk3s5     239362496 189965952  25870940    89%    /System/Volumes/Data
map auto_home            0         0         0   100%    /System/Volumes/Data/home`

	mounts := parseMountsDFOutput(out)
	if len(mounts) != 2 {
		t.Fatalf("mount count=%d, want 2: %+v", len(mounts), mounts)
	}
	if mounts[0].Device != "/dev/disk3s1s1" || mounts[0].MountPoint != "/" {
		t.Fatalf("root mount=%+v", mounts[0])
	}
	if mounts[0].UsePct != 33 {
		t.Fatalf("root use percent=%v, want 33", mounts[0].UsePct)
	}
	if mounts[0].Total != 239362496*1024 || mounts[0].Used != 12274844*1024 || mounts[0].Available != 25870940*1024 {
		t.Fatalf("root byte values=%+v", mounts[0])
	}
	if mounts[1].MountPoint != "/System/Volumes/Data" || mounts[1].UsePct != 89 {
		t.Fatalf("data mount=%+v", mounts[1])
	}
}

func TestParseMountsDFOutputDarwinExtendedColumns(t *testing.T) {
	t.Parallel()

	out := `Filesystem     1024-blocks      Used Available Capacity iused      ifree %iused Mounted on
/dev/disk3s1s1   239362496  12274844  25870940    33%  458726 258709400    0%   /
devfs                  197       197         0   100%     684          0  100%   /dev
/dev/disk3s5     239362496 189965952  25870940    89% 2169288 258709400    1%   /System/Volumes/Data`

	mounts := parseMountsDFOutput(out)
	if len(mounts) != 2 {
		t.Fatalf("mount count=%d, want 2: %+v", len(mounts), mounts)
	}
	if mounts[0].MountPoint != "/" || mounts[0].UsePct != 33 {
		t.Fatalf("root mount=%+v", mounts[0])
	}
	if mounts[1].MountPoint != "/System/Volumes/Data" || mounts[1].UsePct != 89 {
		t.Fatalf("data mount=%+v", mounts[1])
	}
}
