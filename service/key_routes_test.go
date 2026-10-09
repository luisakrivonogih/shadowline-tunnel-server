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
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
)

func TestStreamHandlerUsesTheKeysRoute(t *testing.T) {
	listener := makeLocalhostListener(t)
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	require.NoError(t, err)
	keyID := cipherList.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).ID

	var mu sync.Mutex
	var routed []string
	keyDialer := transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		mu.Lock()
		routed = append(routed, addr)
		mu.Unlock()
		return MakeValidatingTCPStreamDialer(allowAll, 0).DialStream(ctx, addr)
	})
	sh, _ := NewShadowsocksHandlers(
		WithCiphers(cipherList),
		WithStreamDialer(MakeValidatingTCPStreamDialer(allowAll, 0)),
		WithKeyRoutes(map[string]KeyRoute{keyID: {StreamDialer: keyDialer}}),
	)
	go StreamServe(WrapStreamAcceptFunc(listener.AcceptTCP), func(ctx context.Context, conn transport.StreamConn) {
		sh.HandleStream(ctx, conn, &NoOpTCPConnMetrics{})
	})
	defer listener.Close()

	discardListener, discardWait := startDiscardServer(t)
	defer func() { discardListener.Close(); discardWait.Wait() }()
	target := discardListener.Addr().String()
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	_, err = conn.Write(makeClientBytesBasic(t, firstCipher(cipherList), target))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(routed) == 1 && routed[0] == target
	}, 2*time.Second, 20*time.Millisecond)
	conn.Close()
}

func TestMakeKeyRoute(t *testing.T) {
	direct, err := MakeKeyRoute(0, "", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, direct.StreamDialer)
	require.NotNil(t, direct.PacketListener)

	upstream, err := MakeKeyRoute(0, "10.201.0.1:1080", time.Minute)
	require.NoError(t, err)
	require.Same(t, upstream.StreamDialer, upstream.PacketListener) // one SOCKS5 client carries both
}
