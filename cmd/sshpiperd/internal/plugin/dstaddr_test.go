package plugin

import "testing"

func TestInitialMetadataDstAddr(t *testing.T) {
	withAddr := mockConnMetadata{localAddr: mockAddr("203.0.113.10:22")}
	m := initialMetadata(withAddr)
	if got := m[MetaDstAddr]; got != "203.0.113.10:22" {
		t.Fatalf("%s = %q, want 203.0.113.10:22", MetaDstAddr, got)
	}

	noAddr := mockConnMetadata{}
	m = initialMetadata(noAddr)
	if m == nil {
		t.Fatal("metadata map must never be nil: plugins write into it")
	}
	if _, ok := m[MetaDstAddr]; ok {
		t.Fatal("dst_addr must be absent when the local address is unknown")
	}
}
