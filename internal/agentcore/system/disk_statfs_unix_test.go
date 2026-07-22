//go:build linux || darwin || freebsd

package system

import "testing"

func TestSaturatingBlockBytes(t *testing.T) {
	tests := []struct {
		name      string
		blocks    uint64
		blockSize uint64
		want      uint64
	}{
		{name: "zero blocks", blocks: 0, blockSize: 4096, want: 0},
		{name: "zero block size", blocks: 10, blockSize: 0, want: 0},
		{name: "ordinary product", blocks: 10, blockSize: 4096, want: 40960},
		{name: "overflow saturates", blocks: ^uint64(0), blockSize: 2, want: ^uint64(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := saturatingBlockBytes(tt.blocks, tt.blockSize); got != tt.want {
				t.Fatalf("saturatingBlockBytes(%d, %d)=%d, want %d", tt.blocks, tt.blockSize, got, tt.want)
			}
		})
	}
}
