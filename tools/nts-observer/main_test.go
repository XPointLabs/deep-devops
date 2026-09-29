package main

import (
	"encoding/binary"
	"testing"
)

func packet() []byte {
	p := make([]byte, 48+36+40)
	p[0] = 0x24
	binary.BigEndian.PutUint16(p[48:], 0x0104)
	binary.BigEndian.PutUint16(p[50:], 36)
	binary.BigEndian.PutUint16(p[84:], 0x0404)
	binary.BigEndian.PutUint16(p[86:], 40)
	binary.BigEndian.PutUint16(p[88:], 16)
	binary.BigEndian.PutUint16(p[90:], 16)
	return p
}
func TestPacketGuard(t *testing.T) {
	if validatePacket(packet()) != nil {
		t.Fatal("valid bounded framing rejected")
	}
	cases := [][]byte{nil, make([]byte, 47), append(packet(), 0), packet()[:84]}
	for _, off := range []int{0, 50, 86, 88, 90} {
		p := packet()
		p[off] = 255
		cases = append(cases, p)
	}
	p := packet()
	binary.BigEndian.PutUint16(p[48:], 0x0204)
	cases = append(cases, p)
	for _, p := range cases {
		if validatePacket(p) == nil {
			t.Fatal("hostile packet accepted")
		}
	}
}
func TestSourcePolicyInput(t *testing.T) {
	s := source{ID: "0101010101010101010101010101010101010101010101010101010101010101",
		Host: "time.cloudflare.com", Port: 4460, Pin: "0202020202020202020202020202020202020202020202020202020202020202", Radius: 5}
	if !validSource(s) {
		t.Fatal("valid policy tuple rejected")
	}
	for _, h := range []string{"", "127.0.0.1", "Time.Cloudflare.com", "time.cloudflare.com.", "bad_name.invalid"} {
		bad := s
		bad.Host = h
		if validSource(bad) {
			t.Fatal("noncanonical host accepted")
		}
	}
	s.Radius = 11
	if validSource(s) {
		t.Fatal("excessive radius accepted")
	}
}
