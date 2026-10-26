package x11input

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xtest"
)

// A protocol peer, not a physical X server. The real XGB/XTEST client must emit
// exactly the requested keycodes and no XKB group or modifier requests.
func TestInternalX11WireSendsOnlyRequestedPhysicalKeys(t *testing.T) {
	for _, mode := range []string{"available", "missing XTEST"} {
		t.Run(mode, func(t *testing.T) {
			available := mode == "available"
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			type event struct{ kind, code byte }
			finished := make(chan error, 1)
			var events []event
			go func() {
				serve := func() error {
					header := make([]byte, 12)
					if _, err := io.ReadFull(server, header); err != nil {
						return err
					}
					if header[0] != 'l' {
						return fmt.Errorf("unexpected X11 byte order")
					}
					pad := func(n uint16) int64 { return int64((n + 3) &^ 3) }
					if _, err := io.CopyN(io.Discard, server, pad(binary.LittleEndian.Uint16(header[6:]))+pad(binary.LittleEndian.Uint16(header[8:]))); err != nil {
						return err
					}
					setup := make([]byte, 40)
					setup[0] = 1
					binary.LittleEndian.PutUint16(setup[2:], 11)
					binary.LittleEndian.PutUint16(setup[6:], 8)
					binary.LittleEndian.PutUint32(setup[12:], 1<<22)
					binary.LittleEndian.PutUint32(setup[16:], (1<<22)-1)
					if _, err := server.Write(setup); err != nil {
						return err
					}
					for sequence := uint16(1); ; sequence++ {
						header := make([]byte, 4)
						if _, err := io.ReadFull(server, header); err != nil {
							if err == io.EOF {
								return nil
							}
							return err
						}
						size := int(binary.LittleEndian.Uint16(header[2:])) * 4
						if size < 4 || size > 4096 {
							return fmt.Errorf("invalid X11 request length")
						}
						request := append(header, make([]byte, size-4)...)
						if _, err := io.ReadFull(server, request[4:]); err != nil {
							return err
						}
						reply := make([]byte, 32)
						reply[0] = 1
						binary.LittleEndian.PutUint16(reply[2:], sequence)
						switch request[0] {
						case 98: // QueryExtension: permit XTEST only, never XKEYBOARD.
							if len(request) != 16 || string(request[8:13]) != "XTEST" {
								return fmt.Errorf("unexpected extension request")
							}
							if available {
								reply[8], reply[9] = 1, 151
							}
						case 151:
							if len(request) != 36 || request[1] != 2 {
								return fmt.Errorf("unexpected XTEST request")
							}
							for _, value := range request[6:] {
								if value != 0 {
									return fmt.Errorf("unexpected modifier/group payload")
								}
							}
							events = append(events, event{request[4], request[5]})
							continue
						case 43: // GetInputFocus: XGB's checked-request barrier.
						default:
							return fmt.Errorf("unexpected X11 request opcode %d", request[0])
						}
						if _, err := server.Write(reply); err != nil {
							return err
						}
					}
				}
				finished <- serve()
			}()
			conn, err := xgb.NewConnNetWithCookieHex(client, strings.Repeat("00", 16))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := xtest.Init(conn); (err == nil) != available {
				t.Fatalf("XTEST capability available=%v error=%v", available, err)
			}
			if available {
				if err := sendKeys(conn, Request{Press: true, Keys: []byte{50, 62}}); err != nil {
					t.Fatal(err)
				}
				if err := sendKeys(conn, Request{Keys: []byte{62, 50}}); err != nil {
					t.Fatal(err)
				}
			}
			conn.Close()
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			var want []event
			if available {
				want = []event{{2, 50}, {2, 62}, {3, 62}, {3, 50}}
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("physical wire events=%v want=%v", events, want)
			}
		})
	}
}
