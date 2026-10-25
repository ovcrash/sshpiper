package sshkex

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// refValue reads "key: value" from a .ref file written by
// relay-dev/spikes/capture_client.py (reference computed in Python).
func refValue(t *testing.T, ref, key string) string {
	t.Helper()
	for _, line := range strings.Split(ref, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), key+": "); ok {
			return v
		}
	}
	t.Fatalf("key %q not found in reference", key)
	return ""
}

func TestCaptureRealClients(t *testing.T) {
	bins, err := filepath.Glob("testdata/*.bin")
	if err != nil || len(bins) == 0 {
		t.Fatalf("no testdata: %v", err)
	}

	for _, bin := range bins {
		data, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := os.ReadFile(strings.TrimSuffix(bin, ".bin") + ".ref")
		if err != nil {
			t.Fatal(err)
		}

		for _, chunk := range []int{1, 7, 100, len(data)} {
			t.Run(filepath.Base(bin)+"/chunk"+itoa(chunk), func(t *testing.T) {
				var c Capture
				for i := 0; i < len(data); i += chunk {
					end := min(i+chunk, len(data))
					c.Write(data[i:end])
				}

				version, kex, err := c.Result()
				if err != nil {
					t.Fatalf("Result: %v", err)
				}
				if want := refValue(t, string(ref), "version"); version != want {
					t.Errorf("version = %q, want %q", version, want)
				}
				if want := refValue(t, string(ref), "hasshAlgorithms"); kex.HASSHAlgorithms() != want {
					t.Errorf("hasshAlgorithms mismatch:\n got %s\nwant %s", kex.HASSHAlgorithms(), want)
				}
				if want := refValue(t, string(ref), "hassh"); kex.HASSH() != want {
					t.Errorf("hassh = %s, want %s", kex.HASSH(), want)
				}
				if !c.Done() {
					t.Error("capture should be done once the packet is complete")
				}
			})
		}
	}
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{digits[n%10]}, b...)
	}
	return string(b)
}

func TestCaptureIncomplete(t *testing.T) {
	data, err := os.ReadFile("testdata/ssh-98p1.bin")
	if err != nil {
		t.Fatal(err)
	}

	var c Capture
	c.Write(data[:len(data)-1])
	if _, _, err := c.Result(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Result with a missing byte: err = %v, want ErrIncomplete", err)
	}
	if c.Done() {
		t.Error("capture should not be done on a partial packet")
	}

	c.Write(data[len(data)-1:])
	if _, _, err := c.Result(); err != nil {
		t.Fatalf("Result after last byte: %v", err)
	}
}

func TestCaptureBounded(t *testing.T) {
	var c Capture
	junk := make([]byte, 1000)
	for range 200 {
		c.Write(junk)
	}
	if len(c.buf) > MaxCaptureBytes {
		t.Fatalf("buffered %d bytes, limit is %d", len(c.buf), MaxCaptureBytes)
	}
	if !c.Done() {
		t.Error("capture should stop once the limit is reached")
	}
}

func TestCaptureRejectsNonKexInit(t *testing.T) {
	// version line, then a packet of length 6 whose payload starts with 21.
	pkt := []byte("SSH-2.0-x\r\n\x00\x00\x00\x06\x04\x15abcd")
	var c Capture
	c.Write(pkt)
	if _, _, err := c.Result(); !errors.Is(err, ErrNotKexInit) {
		t.Fatalf("err = %v, want ErrNotKexInit", err)
	}
}

func TestParseKexInitTruncated(t *testing.T) {
	payload := append([]byte{msgKexInit}, make([]byte, 16)...)
	payload = append(payload, 0, 0, 0, 200) // list claims 200 bytes, none follow
	if _, err := ParseKexInit(payload); err == nil {
		t.Fatal("expected an error for a truncated name-list")
	}
}
