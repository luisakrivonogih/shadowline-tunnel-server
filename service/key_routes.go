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
	"fmt"
	"net"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/socks5"
	onet "golang.getoutline.org/tunnel-server/net"
)

// KeyRoute is one access key's own way out: the dialer and packet listener
// used for the traffic of clients authenticated with that key, instead of
// the service's.
type KeyRoute struct {
	StreamDialer   transport.StreamDialer
	PacketListener transport.PacketListener
}

// MakeKeyRoute builds a key's route. A non-zero fwmark is set as SO_MARK on
// every socket opened for the key (policy routing, traffic shaping). With
// a socks5 address ("host:port"), the key's TCP and UDP traffic is sent to
// that SOCKS5 server instead of directly; destinations are then the
// upstream's to validate.
func MakeKeyRoute(fwmark uint, socks5Address string, natTimeout time.Duration) (KeyRoute, error) {
	if socks5Address == "" {
		return KeyRoute{
			StreamDialer:   MakeValidatingTCPStreamDialer(onet.RequirePublicIP, fwmark),
			PacketListener: MakeTargetUDPListener(onet.RequirePublicIP, natTimeout, fwmark),
		}, nil
	}
	allowAny := func(net.IP) error { return nil }
	client, err := socks5.NewClient(&transport.StreamDialerEndpoint{
		Dialer:  MakeValidatingTCPStreamDialer(allowAny, fwmark),
		Address: socks5Address,
	})
	if err != nil {
		return KeyRoute{}, fmt.Errorf("socks5 upstream %v: %w", socks5Address, err)
	}
	client.EnablePacket(markedUDPDialer(fwmark))
	return KeyRoute{StreamDialer: client, PacketListener: client}, nil
}

// WithKeyRoutes option function: per access key ID, that key's route.
func WithKeyRoutes(routes map[string]KeyRoute) Option {
	return func(s *ssService) {
		s.keyRoutes = routes
	}
}
