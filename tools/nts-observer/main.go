// Independent NTS observation adapter. No OS clock offset becomes time authority.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"
)

type source struct {
	ID     string `json:"id"`
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	Pin    string `json:"pin"`
	Radius uint16 `json:"radius"`
}
type request struct {
	Sources []source `json:"sources"`
}
type observation struct {
	ID            string `json:"id"`
	UnixSeconds   int64  `json:"unixSeconds"`
	RadiusSeconds uint16 `json:"radiusSeconds"`
}
type response struct {
	Observations []observation `json:"observations"`
}
type peer struct {
	session *nts.Session
	retry   time.Time
	backoff time.Duration
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validSource(s source) bool {
	id, a := hex.DecodeString(s.ID)
	pin, b := hex.DecodeString(s.Pin)
	if a != nil || b != nil || len(id) != 32 || len(pin) != 32 ||
		s.ID != strings.ToLower(s.ID) || s.Pin != strings.ToLower(s.Pin) ||
		s.Port == 0 || s.Radius < 1 || s.Radius > 10 ||
		len(s.Host) > 253 || net.ParseIP(s.Host) != nil {
		return false
	}
	for _, label := range strings.Split(s.Host, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return !allZero(id) && !allZero(pin)
}
func allZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}

// Pre-crypto framing guard for the provider's packet parser. Missing AEAD/UID,
// malformed nonce slices and unauthenticated trailing data fail before provider code.
type guardedExtension struct{}

func (guardedExtension) ProcessQuery(_ *bytes.Buffer) error  { return nil }
func (guardedExtension) ProcessResponse(packet []byte) error { return validatePacket(packet) }
func validatePacket(packet []byte) error {
	bad := errors.New("invalid authenticated packet framing")
	if len(packet) < 48 || len(packet) > 65535 || packet[0]&7 != 4 || (packet[0]>>3)&7 != 4 {
		return bad
	}
	uid, auth := false, false
	for off := 48; off < len(packet); {
		if len(packet)-off < 4 || auth {
			return bad
		}
		typ := binary.BigEndian.Uint16(packet[off:])
		size := int(binary.BigEndian.Uint16(packet[off+2:]))
		if size < 4 || size%4 != 0 || size > len(packet)-off {
			return bad
		}
		body := packet[off+4 : off+size]
		switch typ {
		case 0x0104:
			if uid || len(body) != 32 {
				return bad
			}
			uid = true
		case 0x0204:
			return bad // server cookies belong inside authenticated ciphertext
		case 0x0404:
			if !uid || len(body) < 4 {
				return bad
			}
			n := int(binary.BigEndian.Uint16(body))
			c := int(binary.BigEndian.Uint16(body[2:]))
			if (n != 12 && n != 16) || c < 16 || 4+((n+3)&^3)+((c+3)&^3) != len(body) {
				return bad
			}
			auth = true
		}
		off += size
	}
	if !uid || !auth {
		return bad
	}
	return nil
}

func (p *peer) observe(s source) (o observation, err error) {
	// Provider panic is not an observation and cannot leak an unauthenticated time.
	defer func() {
		if recover() != nil {
			p.session = nil
			err = errors.New("provider failed")
		}
	}()
	if time.Until(p.retry) > 0 {
		return o, errors.New("backoff")
	}
	if p.session == nil {
		pin, _ := hex.DecodeString(s.Pin)
		p.session, err = nts.NewSessionWithOptions(net.JoinHostPort(s.Host, itoaPort(s.Port)), &nts.SessionOptions{
			Timeout: 4 * time.Second,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: s.Host,
				VerifyConnection: func(state tls.ConnectionState) error {
					if state.NegotiatedProtocol != "ntske/1" || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
						return errors.New("TLS closure rejected")
					}
					actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
					if subtle.ConstantTimeCompare(actual[:], pin) != 1 {
						return errors.New("pin rejected")
					}
					return nil
				}},
		})
		if err != nil {
			p.fail()
			return o, err
		}
	}
	start := time.Now() // elapsed measurements use Go's monotonic component
	r, err := p.session.QueryWithOptions(&ntp.QueryOptions{Version: 4, Timeout: 4 * time.Second, Extensions: []ntp.Extension{guardedExtension{}}})
	elapsed := time.Since(start)
	if err == nil {
		err = r.Validate()
	} // includes NTS authentication result
	if err != nil {
		p.fail()
		return o, err
	}
	// The authenticated server transmit time, not local wall time + ClockOffset.
	// Full RTT (including provider processing) bounds unknown one-way delay.
	radius := r.RootDelay/2 + r.RootDispersion + r.Precision + elapsed + time.Second
	if r.RootDelay < 0 || r.RootDispersion < 0 || r.Precision < 0 || radius < time.Second || radius > time.Duration(s.Radius)*time.Second || r.Time.Unix() <= 0 || r.Version != 4 {
		p.fail()
		return o, errors.New("source interval rejected")
	}
	p.backoff = 0
	p.retry = time.Time{} // reset only after KE plus authenticated NTP
	return observation{s.ID, r.Time.Unix(), uint16(math.Ceil(radius.Seconds()))}, nil
}
func itoaPort(p uint16) string { return strconv.Itoa(int(p)) }
func (p *peer) fail() {
	p.session = nil
	if p.backoff == 0 {
		p.backoff = 10 * time.Second
	} else {
		p.backoff = p.backoff * 3 / 2
	}
	if p.backoff > 5*24*time.Hour {
		p.backoff = 5 * 24 * time.Hour
	}
	p.retry = time.Now().Add(p.backoff)
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 16384)
	writer := bufio.NewWriter(os.Stdout)
	peers := map[string]*peer{}
	var fixed []source
	for scanner.Scan() {
		var req request
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF || len(req.Sources) < 2 || len(req.Sources) > 8 {
			os.Exit(2)
		}
		ids := map[string]bool{}
		for _, s := range req.Sources {
			if !validSource(s) || ids[s.ID] {
				os.Exit(2)
			}
			ids[s.ID] = true
		}
		if fixed == nil {
			fixed = req.Sources
		} else {
			a, _ := json.Marshal(fixed)
			b, _ := json.Marshal(req.Sources)
			if string(a) != string(b) {
				os.Exit(2)
			}
		}
		observations := make([]observation, len(req.Sources))
		ok := make([]bool, len(req.Sources))
		var wg sync.WaitGroup
		for i, s := range req.Sources {
			if peers[s.ID] == nil {
				peers[s.ID] = &peer{}
			}
			p := peers[s.ID]
			wg.Add(1)
			go func(i int, s source, p *peer) {
				defer wg.Done()
				o, e := p.observe(s)
				if e == nil {
					observations[i] = o
					ok[i] = true
				}
			}(i, s, p)
		}
		wg.Wait()
		result := response{Observations: []observation{}}
		for i, o := range observations {
			if ok[i] {
				result.Observations = append(result.Observations, o)
			}
		}
		if json.NewEncoder(writer).Encode(result) != nil || writer.Flush() != nil {
			os.Exit(3)
		}
	}
	if scanner.Err() != nil {
		os.Exit(2)
	}
}
