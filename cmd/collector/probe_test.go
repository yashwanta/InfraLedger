package main

import "testing"

func TestParseTTL(t *testing.T) {
	cases := map[string]int{
		"Reply from 10.20.30.9: bytes=32 time=3ms TTL=128":        128,
		"64 bytes from 10.20.30.9: icmp_seq=1 ttl=64 time=0.4 ms": 64,
		"Reply from 10.20.30.2: Destination host unreachable.":    0,
		"Antwort von 10.20.30.9: Bytes=32 Zeit<1ms TTL=255":       255,
		"Request timed out.": 0,
	}
	for out, want := range cases {
		if got := parseTTL(out); got != want {
			t.Fatalf("%q: got %d want %d", out, got, want)
		}
	}
}

func TestNetBIOSNodeStatus(t *testing.T) {
	q := nbstatQuery()
	if len(q) != 50 || q[12] != 0x20 || q[13] != 'C' || q[14] != 'K' || q[47] != 0x21 {
		t.Fatalf("bad query % x", q)
	}
	entry := func(name string, suffix byte, group bool) []byte {
		b := []byte(name)
		for len(b) < 15 {
			b = append(b, ' ')
		}
		flags := byte(0x04)
		if group {
			flags |= 0x80
		}
		return append(b, suffix, flags, 0x00)
	}
	resp := append([]byte{0x4e, 0x42, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0}, q[12:46]...)
	resp = append(resp, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x41, 3)
	resp = append(resp, entry("OFFICE-PC", 0x00, false)...)
	resp = append(resp, entry("WORKGROUP", 0x00, true)...)
	resp = append(resp, entry("OFFICE-PC", 0x20, false)...)
	resp = append(resp, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
	name, group := parseNBStat(resp)
	if name != "OFFICE-PC" || group != "WORKGROUP" {
		t.Fatalf("got %q %q", name, group)
	}
	if n, _ := parseNBStat(resp[:40]); n != "" {
		t.Fatal("truncated packet parsed")
	}
	if n, _ := parseNBStat(q); n != "" {
		t.Fatal("query parsed as a response")
	}
}
