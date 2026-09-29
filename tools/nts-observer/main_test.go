package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

type fakeConn struct{ closed chan struct{} }

func (c fakeConn) Close() error { close(c.closed); return nil }

func TestRaceDialSkipsBlackholedAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	got, err := raceDial(ctx, 3, 20*time.Millisecond, func(ctx context.Context, i int) (fakeConn, error) {
		if i == 0 {
			<-ctx.Done() // unreachable member of the address set
			return fakeConn{}, ctx.Err()
		}
		return fakeConn{closed: make(chan struct{})}, nil
	})
	if err != nil || got.closed == nil || time.Since(start) > time.Second {
		t.Fatalf("reachable address was not used promptly: %v", err)
	}
}

func TestRaceDialClosesLateWinnerAndReportsFailure(t *testing.T) {
	late := fakeConn{closed: make(chan struct{})}
	_, err := raceDial(context.Background(), 2, 0, func(_ context.Context, i int) (fakeConn, error) {
		if i == 1 {
			time.Sleep(50 * time.Millisecond)
			return late, nil
		}
		return fakeConn{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-late.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("unused connection leaked")
	}
	if _, err := raceDial(context.Background(), 2, 0, func(context.Context, int) (fakeConn, error) {
		return fakeConn{}, errors.New("refused")
	}); err == nil {
		t.Fatal("all-failed race reported success")
	}
	if _, err := raceDial(context.Background(), 0, 0, func(context.Context, int) (fakeConn, error) {
		return fakeConn{}, nil
	}); err == nil {
		t.Fatal("empty address set accepted")
	}
}
func TestTimeoutClassification(t *testing.T) {
	if !isTimeout(fmt.Errorf("read udp: %w", os.ErrDeadlineExceeded)) {
		t.Fatal("lost datagram not treated as retryable")
	}
	if isTimeout(nil) || isTimeout(errors.New("authentication failed")) {
		t.Fatal("non-timeout classified as retryable")
	}
}
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
