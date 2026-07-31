// Copyright 2026 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file implements the server side of "Shadowline Extended Framing v1",
// an optional, backwards-compatible extension layered on top of a normal
// Shadowsocks TCP stream.
//
// Design constraints that shaped this protocol:
//
//   - Shadowsocks has no handshake: the server cannot ask a connecting client
//     "do you speak the extension?" without itself becoming a distinguishing
//     signal. So capability discovery cannot happen on the wire; it happens
//     out of band, at access-key issuance time (the `shadowline=1` marker in
//     the access key tells a Shadowline client that this particular server
//     supports the extension).
//   - Any byte injected into the middle of a stock AEAD Shadowsocks stream
//     that the peer doesn't know how to strip will be forwarded verbatim to
//     the proxied destination (or delivered to the local application),
//     corrupting whatever protocol is being tunneled. So a server MUST be
//     able to tell, per-connection, whether the specific client on the other
//     end is extension-aware, and fall back to byte-for-bit vanilla
//     Shadowsocks behavior whenever it isn't.
//
// Per-connection detection is done with a marker that is:
//   - Deterministic given the pre-shared secret and the connection's salt
//     (so both ends can compute it independently, no coordination needed).
//   - Indistinguishable from random ciphertext to anyone without the secret
//     (HMAC-SHA256 over a per-connection nonce, truncated to 8 bytes), so it
//     adds no fingerprint of its own.
//   - Placed immediately after the SOCKS target address in the decrypted
//     stream, i.e. as the first bytes the client's Shadowline wrapper ever
//     writes to the already-open Shadowsocks connection.
//
// A vanilla client's first application bytes will match this marker with
// probability 2^-64: cryptographically negligible.
//
// Once a connection is confirmed extended, all further bytes (both
// directions) are wrapped in a tiny frame: [tag:1][len:2 BE][payload:len].
// tag 0x01 (data) is passed through untouched; tag 0x02 (pad) is discarded.
// This lets either side inject genuine cover-traffic chunks that the peer
// safely drops, instead of corrupting the tunneled stream -- which is the
// bug this design specifically avoids.
package service

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.org/x/crypto/hkdf"
)

const (
	// shadowlineExtMarkerLen is the length, in bytes, of the per-connection
	// extension marker.
	shadowlineExtMarkerLen = 8

	// Frame tags for Shadowline Extended Framing v1.
	shadowlineFrameTagData byte = 0x01
	shadowlineFrameTagPad  byte = 0x02

	// shadowlineMaxFrameLen bounds a single frame's payload so it always
	// fits comfortably inside one Shadowsocks AEAD chunk (max 0x3FFF bytes).
	shadowlineMaxFrameLen = 4096

	shadowlineFrameHeaderLen = 3 // 1 tag byte + 2 length bytes

	// Server-side cover-traffic pacing. Deliberately modest: the goal is to
	// blur size/timing fingerprints, not to burn bandwidth.
	serverPadMinIntervalMs = 400
	serverPadMaxIntervalMs = 2500
	serverPadMinLen        = 16
	serverPadMaxLen        = 512
)

// shadowlineExtLabel scopes the HKDF derivation so this marker key can never
// collide with the server's other secret-derived values (e.g. the salt
// marker in server_salt.go, which uses a different label).
var shadowlineExtLabel = []byte("shadowline-ext-marker-v1")

// deriveExtMarkerKey derives a dedicated HMAC key from the access key's
// plaintext secret. Mirrors the HKDF-over-shared-secret pattern already used
// by NewServerSaltGenerator, with a distinct label.
func deriveExtMarkerKey(secret string) []byte {
	keySource := hkdf.New(crypto.SHA256.New, []byte(secret), nil, shadowlineExtLabel)
	key := make([]byte, crypto.SHA256.Size())
	io.ReadFull(keySource, key) //nolint:errcheck // HKDF-SHA256 read of a fixed, small size never fails.
	return key
}

// computeExtMarker returns the 8-byte per-connection marker that identifies
// a Shadowline-extended stream to a peer holding the same secret.
func computeExtMarker(markerKey, salt []byte) []byte {
	mac := hmac.New(crypto.SHA256.New, markerKey)
	mac.Write(salt) //nolint:errcheck // hash.Hash.Write never returns an error.
	return mac.Sum(nil)[:shadowlineExtMarkerLen]
}

// shadowlineNegotiationTimeout bounds how long the server waits, right
// after the target address, for the extension marker before assuming this
// is a vanilla (non-Shadowline) connection.
//
// This must not be unbounded: Shadowsocks proxies arbitrary TCP protocols,
// including ones where the *server* speaks first (SMTP, IMAP, many game
// and RPC protocols) or where the client sends a short request and then
// waits. A vanilla client in either case may never send an 8th byte, so
// blocking on io.ReadFull without a deadline would stall the connection
// forever. A genuine Shadowline client, by contrast, writes its marker as
// its own synchronous write immediately after connecting (see the client's
// config_shadowline_ext.go), so it always arrives within one network RTT.
const shadowlineNegotiationTimeout = 700 * time.Millisecond

// isBenignShortRead reports whether err is the kind of "nothing more
// arrived" condition -- a clean EOF with zero bytes read, or a negotiation-
// window timeout -- that simply means "this is not a Shadowline client".
//
// Deliberately excluded: io.ErrUnexpectedEOF. Because each Shadowsocks
// chunk is only yielded once it's fully received and authenticated, an
// EOF while a new chunk is partway through being assembled (some, but not
// all, of the expected bytes for it arrived before the socket closed) is
// reported as io.ErrUnexpectedEOF, and it means the same thing it would
// have meant one layer up in proxyConnection's relay loop: the stream was
// truncated or corrupted mid-chunk. That must surface as a real connection
// error, not be swallowed as "just a vanilla client".
func isBenignShortRead(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// negotiateServerExtension inspects the bytes immediately following the
// target address on a freshly-authenticated Shadowsocks stream. If they
// match this connection's extension marker, it returns a StreamConn using
// Shadowline Extended Framing v1 (with server-side cover traffic). If
// nothing arrives within the negotiation window (timeout, clean EOF, or a
// short read that isn't the marker), it returns a StreamConn that behaves
// exactly like the unmodified input, with the peeked bytes replayed so no
// data is lost. This is what lets the exact same access key be used from a
// vanilla Outline client and a Shadowline client on the very same server.
//
// A genuine read error (e.g. a corrupted Shadowsocks chunk) is returned
// as-is rather than swallowed, so callers keep classifying it the same way
// a failure at this point in the stream would be classified without this
// extension.
func negotiateServerExtension(conn transport.StreamConn, secret string, salt []byte) (transport.StreamConn, error) {
	marker := computeExtMarker(deriveExtMarkerKey(secret), salt)

	// Best-effort deadline: if it can't be set, fall through and let the
	// read below block on the connection's existing deadline (or none),
	// same as any other read on this conn.
	_ = conn.SetReadDeadline(time.Now().Add(shadowlineNegotiationTimeout))
	peeked := make([]byte, len(marker))
	n, err := io.ReadFull(conn, peeked)
	_ = conn.SetReadDeadline(time.Time{})

	if err != nil && !isBenignShortRead(err) {
		return nil, err
	}
	if err != nil || !hmac.Equal(peeked[:n], marker) {
		// Not an extended client, or nothing arrived within the
		// negotiation window. Replay whatever we peeked and continue
		// exactly as vanilla Shadowsocks.
		return transport.WrapConn(conn, io.MultiReader(bytes.NewReader(peeked[:n]), conn), conn), nil
	}

	var writeMu sync.Mutex
	fw := &shadowlineFrameWriter{w: conn, mu: &writeMu}
	fr := &shadowlineFrameReader{r: conn}
	pad := newShadowlinePadInjector(fw, serverPadMinIntervalMs, serverPadMaxIntervalMs, serverPadMinLen, serverPadMaxLen)
	return &shadowlineExtConn{StreamConn: transport.WrapConn(conn, fr, fw), pad: pad}, nil
}

// shadowlineFrameReader reads [tag][len][payload] frames from the
// underlying (already Shadowsocks-decrypted) stream, transparently
// discarding pad frames and exposing only data frame payloads to Read.
type shadowlineFrameReader struct {
	r      io.Reader
	mu     sync.Mutex
	buf    bytes.Buffer
	header [shadowlineFrameHeaderLen]byte
}

func (fr *shadowlineFrameReader) Read(p []byte) (int, error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	for fr.buf.Len() == 0 {
		if _, err := io.ReadFull(fr.r, fr.header[:]); err != nil {
			return 0, err
		}
		tag := fr.header[0]
		payloadLen := int(binary.BigEndian.Uint16(fr.header[1:3]))
		if payloadLen > shadowlineMaxFrameLen {
			return 0, fmt.Errorf("shadowline: frame length %d exceeds max %d", payloadLen, shadowlineMaxFrameLen)
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(fr.r, payload); err != nil {
			return 0, err
		}
		switch tag {
		case shadowlineFrameTagData:
			fr.buf.Write(payload)
		case shadowlineFrameTagPad:
			// Cover traffic: silently discarded, loop for the next frame.
		default:
			return 0, fmt.Errorf("shadowline: unknown frame tag 0x%02x", tag)
		}
	}
	return fr.buf.Read(p)
}

// shadowlineFrameWriter frames outgoing bytes as data frames, splitting
// writes larger than shadowlineMaxFrameLen. mu is shared with any
// concurrent pad injector writing to the same underlying stream, since the
// Shadowsocks Writer requires single-threaded access per write.
type shadowlineFrameWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (fw *shadowlineFrameWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), shadowlineMaxFrameLen)
		if err := fw.writeFrame(shadowlineFrameTagData, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (fw *shadowlineFrameWriter) writeFrame(tag byte, payload []byte) error {
	if len(payload) > shadowlineMaxFrameLen {
		return errors.New("shadowline: payload exceeds max frame length")
	}
	buf := make([]byte, shadowlineFrameHeaderLen+len(payload))
	buf[0] = tag
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(payload)))
	copy(buf[shadowlineFrameHeaderLen:], payload)

	fw.mu.Lock()
	defer fw.mu.Unlock()
	_, err := fw.w.Write(buf)
	return err
}

// shadowlinePadInjector periodically writes pad frames on a jittered
// schedule to blur size and timing fingerprints. Safe to run concurrently
// with real data writes because shadowlineFrameWriter.writeFrame serializes
// access to the underlying stream.
type shadowlinePadInjector struct {
	fw                     *shadowlineFrameWriter
	minIntervalMs, maxIntervalMs int
	minLen, maxLen         int
	stop                   chan struct{}
	stopOnce               sync.Once
	done                   chan struct{}
}

func newShadowlinePadInjector(fw *shadowlineFrameWriter, minIntervalMs, maxIntervalMs, minLen, maxLen int) *shadowlinePadInjector {
	pi := &shadowlinePadInjector{
		fw:            fw,
		minIntervalMs: minIntervalMs,
		maxIntervalMs: maxIntervalMs,
		minLen:        minLen,
		maxLen:        maxLen,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	go pi.loop()
	return pi
}

func (pi *shadowlinePadInjector) loop() {
	defer close(pi.done)
	for {
		delay := time.Duration(randIntRange(pi.minIntervalMs, pi.maxIntervalMs)) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-pi.stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		padLen := randIntRange(pi.minLen, pi.maxLen)
		pad := make([]byte, padLen)
		if _, err := rand.Read(pad); err != nil {
			return
		}
		if err := pi.fw.writeFrame(shadowlineFrameTagPad, pad); err != nil {
			return
		}
	}
}

// Stop halts pad injection. Safe to call multiple times and to call before
// the injector has written anything. Does not block on in-flight writes.
func (pi *shadowlinePadInjector) Stop() {
	pi.stopOnce.Do(func() { close(pi.stop) })
}

// randIntRange returns a cryptographically-random integer in [lo, hi]
// (inclusive). Falls back to lo if the range is empty or invalid.
func randIntRange(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	span := big.NewInt(int64(hi-lo) + 1)
	n, err := rand.Int(rand.Reader, span)
	if err != nil {
		return lo
	}
	return lo + int(n.Int64())
}

// shadowlineExtConn is a transport.StreamConn that also stops its
// associated pad injector goroutine when closed, so extended connections
// don't leak background timers.
type shadowlineExtConn struct {
	transport.StreamConn
	pad *shadowlinePadInjector
}

func (c *shadowlineExtConn) Close() error {
	c.pad.Stop()
	return c.StreamConn.Close()
}

func (c *shadowlineExtConn) CloseWrite() error {
	c.pad.Stop()
	return c.StreamConn.CloseWrite()
}
