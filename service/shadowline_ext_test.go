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

package service

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"

	"github.com/stretchr/testify/require"
)

// TestComputeExtMarkerKnownAnswer pins the marker derivation to a fixed,
// independently-computed test vector that the client's Go implementation
// (outline-apps/client/go/shadowline/configregistry/config_shadowline_ext_test.go)
// asserts the exact same value for. If either side's derivation ever
// drifts -- a changed label, a swapped hash, a different truncation length
// -- this test and its client-side twin catch it immediately, instead of
// only failing silently as "the marker never matches" in the field.
func TestComputeExtMarkerKnownAnswer(t *testing.T) {
	salt, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)
	want, err := hex.DecodeString("59834435c7d779a7")
	require.NoError(t, err)

	got := computeExtMarker(deriveExtMarkerKey("test-vector-secret"), salt)
	require.Equal(t, want, got)
}

func TestComputeExtMarkerIsDeterministicAndSaltDependent(t *testing.T) {
	key := deriveExtMarkerKey("shared-secret")
	salt1 := []byte("0123456789abcdef")
	salt2 := []byte("fedcba9876543210")

	m1a := computeExtMarker(key, salt1)
	m1b := computeExtMarker(key, salt1)
	require.Equal(t, m1a, m1b, "same secret+salt must yield the same marker")
	require.Len(t, m1a, shadowlineExtMarkerLen)

	m2 := computeExtMarker(key, salt2)
	require.NotEqual(t, m1a, m2, "different salts must yield different markers")

	otherKey := deriveExtMarkerKey("different-secret")
	m3 := computeExtMarker(otherKey, salt1)
	require.NotEqual(t, m1a, m3, "different secrets must yield different markers")
}

// tcpLoopback returns a connected pair of real TCP StreamConns, so tests can
// exercise negotiateServerExtension exactly as it runs in production
// (against a genuine net.Conn implementing CloseRead/CloseWrite).
func tcpLoopback(t *testing.T) (client, server transport.StreamConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	serverCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- c
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	select {
	case s := <-serverCh:
		return c.(*net.TCPConn), s.(*net.TCPConn)
	case err := <-errCh:
		t.Fatalf("accept failed: %v", err)
		return nil, nil
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for loopback accept")
		return nil, nil
	}
}

func TestNegotiateServerExtension_VanillaClientPassesThroughUnchanged(t *testing.T) {
	client, server := tcpLoopback(t)
	defer client.Close()
	defer server.Close()

	secret := "test-secret"
	salt := []byte("0123456789abcdef")
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeErrCh <- err
	}()

	wrapped, err := negotiateServerExtension(server, secret, salt)
	require.NoError(t, err)
	require.NoError(t, <-writeErrCh)

	got := make([]byte, len(payload))
	_, err = io.ReadFull(wrapped, got)
	require.NoError(t, err)
	require.Equal(t, payload, got, "a vanilla client's bytes must be forwarded verbatim, marker or not")
}

func TestNegotiateServerExtension_ServerSpeaksFirstProtocolDoesNotHang(t *testing.T) {
	client, server := tcpLoopback(t)
	defer client.Close()
	defer server.Close()

	// The client sends nothing at all after the address, mimicking a
	// protocol where the server is expected to speak first (SMTP, IMAP).
	// negotiateServerExtension must not block waiting for a marker that
	// will never arrive; it should fall back to vanilla well within the
	// test's own timeout.
	done := make(chan error, 1)
	go func() {
		_, err := negotiateServerExtension(server, "test-secret", []byte("saltsaltsaltsalt"))
		done <- err
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("negotiateServerExtension hung waiting for a marker that was never sent")
	}
}

func TestNegotiateServerExtension_ExtendedClientStripsPadFrames(t *testing.T) {
	client, server := tcpLoopback(t)
	defer client.Close()
	defer server.Close()

	secret := "test-secret"
	salt := []byte("saltsaltsaltsalt")
	marker := computeExtMarker(deriveExtMarkerKey(secret), salt)

	writeErrCh := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		buf.Write(marker)
		writeFrame(&buf, shadowlineFrameTagPad, []byte("junk-before"))
		writeFrame(&buf, shadowlineFrameTagData, []byte("hello, "))
		writeFrame(&buf, shadowlineFrameTagPad, []byte("junk-between"))
		writeFrame(&buf, shadowlineFrameTagData, []byte("world"))
		writeFrame(&buf, shadowlineFrameTagPad, []byte("junk-after"))
		_, err := client.Write(buf.Bytes())
		writeErrCh <- err
	}()

	wrapped, err := negotiateServerExtension(server, secret, salt)
	require.NoError(t, err)
	require.NoError(t, <-writeErrCh)

	got := make([]byte, len("hello, world"))
	_, err = io.ReadFull(wrapped, got)
	require.NoError(t, err)
	require.Equal(t, "hello, world", string(got), "pad frames must be transparently discarded, only data frames surfaced")
}

func TestNegotiateServerExtension_MismatchedSecretFallsBackToVanilla(t *testing.T) {
	client, server := tcpLoopback(t)
	defer client.Close()
	defer server.Close()

	clientSalt := []byte("saltsaltsaltsalt")
	// The client computes its marker with a different secret than the
	// server checks against -- e.g. a corrupted or mismatched key. From
	// the server's point of view this must look exactly like a vanilla
	// client: those 8 bytes were just app data.
	wrongMarker := computeExtMarker(deriveExtMarkerKey("wrong-secret"), clientSalt)

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := client.Write(wrongMarker)
		writeErrCh <- err
	}()

	wrapped, err := negotiateServerExtension(server, "real-secret", clientSalt)
	require.NoError(t, err)
	require.NoError(t, <-writeErrCh)

	got := make([]byte, len(wrongMarker))
	_, err = io.ReadFull(wrapped, got)
	require.NoError(t, err)
	require.Equal(t, wrongMarker, got, "bytes that fail the marker check must be replayed, not dropped")
}

func TestShadowlineFrameWriterSplitsOversizedWrites(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	fw := &shadowlineFrameWriter{w: &buf, mu: &mu}

	big := bytes.Repeat([]byte{0x42}, shadowlineMaxFrameLen+100)
	n, err := fw.Write(big)
	require.NoError(t, err)
	require.Equal(t, len(big), n)

	fr := &shadowlineFrameReader{r: &buf}
	got := make([]byte, len(big))
	_, err = io.ReadFull(fr, got)
	require.NoError(t, err)
	require.Equal(t, big, got)
}

// writeFrame is a test-only helper that mirrors shadowlineFrameWriter's
// on-wire format without going through the production type, so the test
// exercises the reader against an independently-constructed frame.
func writeFrame(w io.Writer, tag byte, payload []byte) {
	hdr := make([]byte, shadowlineFrameHeaderLen)
	hdr[0] = tag
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(payload)))
	w.Write(hdr)
	w.Write(payload)
}
