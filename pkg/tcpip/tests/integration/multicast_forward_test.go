// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multicast_forward_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/refsvfs2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/tests/utils"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	incomingNICID = 1
	outgoingNICID = 2
	otherNICID    = 3
	packetTTL     = 64
	routeMinTTL   = 2
)

type addrType int

const (
	emptyAddr addrType = iota
	anyAddr
	linkLocalMulticastAddr
	linkLocalUnicastAddr
	multicastAddr
	otherMulticastAddr
	remoteUnicastAddr
)

type endpointAddrType int

const (
	incomingEndpointAddr endpointAddrType = iota
	otherEndpointAddr
	outgoingEndpointAddr
)

var _ stack.MulticastForwardingEventDispatcher = (*multicastEventDispatcher)(nil)

type onMissingRouteData struct {
	context stack.MulticastPacketContext
}

type onUnexpectedInputInterfaceData struct {
	context                stack.MulticastPacketContext
	expectedInputInterface tcpip.NICID
}

type multicastEventDispatcher struct {
	onMissingRouteData             *onMissingRouteData
	onUnexpectedInputInterfaceData *onUnexpectedInputInterfaceData
}

func (m *multicastEventDispatcher) OnMissingRoute(context stack.MulticastPacketContext) {
	m.onMissingRouteData = &onMissingRouteData{context}
}

func (m *multicastEventDispatcher) OnUnexpectedInputInterface(context stack.MulticastPacketContext, expectedInputInterface tcpip.NICID) {
	m.onUnexpectedInputInterfaceData = &onUnexpectedInputInterfaceData{
		context,
		expectedInputInterface,
	}
}

func addrForProtocol(protocol tcpip.NetworkProtocolNumber, ipv4Addr, ipv6Addr tcpip.Address) tcpip.Address {
	switch protocol {
	case ipv4.ProtocolNumber:
		return ipv4Addr
	case ipv6.ProtocolNumber:
		return ipv6Addr
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func getAddr(protocol tcpip.NetworkProtocolNumber, addrType addrType) tcpip.Address {
	switch addrType {
	case anyAddr:
		return addrForProtocol(protocol, header.IPv4Any, header.IPv6Any)
	case emptyAddr:
		return ""
	case linkLocalMulticastAddr:
		return addrForProtocol(protocol, testutil.MustParse4("224.0.0.1"), testutil.MustParse6("ff02::a"))
	case linkLocalUnicastAddr:
		return addrForProtocol(protocol, testutil.MustParse4("169.254.0.10"), testutil.MustParse6("fe80::a"))
	case multicastAddr:
		return addrForProtocol(protocol, testutil.MustParse4("225.0.0.0"), testutil.MustParse6("ff0e::a"))
	case otherMulticastAddr:
		return addrForProtocol(protocol, testutil.MustParse4("225.0.0.1"), testutil.MustParse6("ff0e::b"))
	case remoteUnicastAddr:
		return addrForProtocol(protocol, utils.RemoteIPv4Addr, utils.RemoteIPv6Addr)
	default:
		panic(fmt.Sprintf("unsupported addrType: %d", addrType))
	}
}

func addrWithPrefixForProtocol(protocol tcpip.NetworkProtocolNumber, ipv4Addr, ipv6Addr tcpip.AddressWithPrefix) tcpip.AddressWithPrefix {
	switch protocol {
	case ipv4.ProtocolNumber:
		return ipv4Addr
	case ipv6.ProtocolNumber:
		return ipv6Addr
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func getEndpointAddr(protocol tcpip.NetworkProtocolNumber, addrType endpointAddrType) tcpip.AddressWithPrefix {
	switch addrType {
	case incomingEndpointAddr:
		return addrWithPrefixForProtocol(protocol, utils.RouterNIC1IPv4Addr.AddressWithPrefix, utils.RouterNIC1IPv6Addr.AddressWithPrefix)
	case otherEndpointAddr:
		return addrWithPrefixForProtocol(protocol, utils.Host1IPv4Addr.AddressWithPrefix, utils.Host1IPv6Addr.AddressWithPrefix)
	case outgoingEndpointAddr:
		return addrWithPrefixForProtocol(protocol, utils.RouterNIC2IPv4Addr.AddressWithPrefix, utils.RouterNIC2IPv6Addr.AddressWithPrefix)
	default:
		panic(fmt.Sprintf("unsupported endpointAddrType: %d", addrType))
	}
}

func checkEchoRequest(t *testing.T, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer, srcAddr, dstAddr tcpip.Address, ttl uint8) {
	switch protocol {
	case ipv4.ProtocolNumber:
		checker.IPv4(t, stack.PayloadSince(pkt.NetworkHeader()),
			checker.SrcAddr(srcAddr),
			checker.DstAddr(dstAddr),
			checker.TTL(ttl),
			checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4Echo),
			),
		)
	case ipv6.ProtocolNumber:
		checker.IPv6(t, stack.PayloadSince(pkt.NetworkHeader()),
			checker.SrcAddr(srcAddr),
			checker.DstAddr(dstAddr),
			checker.TTL(ttl),
			checker.ICMPv6(
				checker.ICMPv6Type(header.ICMPv6EchoRequest),
			),
		)
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func checkEchoReply(t *testing.T, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer, srcAddr, dstAddr tcpip.Address) {
	switch protocol {
	case ipv4.ProtocolNumber:
		checker.IPv4(t, stack.PayloadSince(pkt.NetworkHeader()),
			checker.SrcAddr(srcAddr),
			checker.DstAddr(dstAddr),
			checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4EchoReply),
			),
		)
	case ipv6.ProtocolNumber:
		checker.IPv6(t, stack.PayloadSince(pkt.NetworkHeader()),
			checker.SrcAddr(srcAddr),
			checker.DstAddr(dstAddr),
			checker.ICMPv6(
				checker.ICMPv6Type(header.ICMPv6EchoReply),
			),
		)
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func injectPacket(ep *channel.Endpoint, protocol tcpip.NetworkProtocolNumber, srcAddr, dstAddr tcpip.Address, ttl uint8) {
	switch protocol {
	case ipv4.ProtocolNumber:
		utils.RxICMPv4EchoRequest(ep, srcAddr, dstAddr, ttl)
	case ipv6.ProtocolNumber:
		utils.RxICMPv6EchoRequest(ep, srcAddr, dstAddr, ttl)
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func getProtocolName(protocol tcpip.NetworkProtocolNumber) string {
	switch protocol {
	case ipv4.ProtocolNumber:
		return "IPv4"
	case ipv6.ProtocolNumber:
		return "IPv6"
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func TestAddMulticastRoute(t *testing.T) {
	const unknownNICID = 4

	endpointConfigs := map[tcpip.NICID]endpointAddrType{
		incomingNICID: incomingEndpointAddr,
		outgoingNICID: outgoingEndpointAddr,
		otherNICID:    otherEndpointAddr,
	}

	tests := []struct {
		name                   string
		srcAddr, dstAddr       addrType
		routeIncomingNICID     tcpip.NICID
		routeOutgoingNICID     tcpip.NICID
		omitOutgoingInterfaces bool
		injectPendingPacket    bool
		expectForward          bool
		wantErr                tcpip.Error
	}{
		{
			name:               "no pending packets",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			wantErr:            nil,
		},
		{
			name:                "pending packet forwarded",
			srcAddr:             remoteUnicastAddr,
			dstAddr:             multicastAddr,
			routeIncomingNICID:  incomingNICID,
			routeOutgoingNICID:  outgoingNICID,
			injectPendingPacket: true,
			expectForward:       true,
		},
		{
			name:    "unexpected input interface",
			srcAddr: remoteUnicastAddr,
			dstAddr: multicastAddr,
			// The added route's incoming NICID does not match the pending packet's
			// incoming NICID. As a result, the packet should not be forwarded.
			routeIncomingNICID:  otherNICID,
			routeOutgoingNICID:  outgoingNICID,
			injectPendingPacket: true,
		},
		{
			name:               "multicast source",
			srcAddr:            multicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			wantErr:            &tcpip.ErrBadAddress{},
		},
		{
			name:               "any source",
			srcAddr:            anyAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			wantErr:            &tcpip.ErrBadAddress{},
		},
		{
			name:               "link-local unicast source",
			srcAddr:            linkLocalUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			wantErr:            &tcpip.ErrBadAddress{},
		},
		{
			name:               "empty source",
			srcAddr:            emptyAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			wantErr:            &tcpip.ErrBadAddress{},
		},
		{
			name:               "unicast destination",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            remoteUnicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			wantErr:            &tcpip.ErrBadAddress{},
		},
		{
			name:               "empty destination",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            emptyAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			wantErr:            &tcpip.ErrBadAddress{},
		},
		{
			name:               "link-local multicast destination",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            linkLocalMulticastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			wantErr:            &tcpip.ErrBadAddress{},
		},
		{
			name:               "unknown input NICID",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: unknownNICID,
			routeOutgoingNICID: outgoingNICID,
			wantErr:            &tcpip.ErrUnknownNICID{},
		},
		{
			name:               "unknown output NICID",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: unknownNICID,
			wantErr:            &tcpip.ErrUnknownNICID{},
		},
		{
			name:               "input NIC matches output NIC",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: incomingNICID,
			wantErr:            &tcpip.ErrInputCannotBeOutput{},
		},
		{
			name:                   "empty outgoing interfaces",
			srcAddr:                remoteUnicastAddr,
			dstAddr:                multicastAddr,
			routeIncomingNICID:     incomingNICID,
			routeOutgoingNICID:     outgoingNICID,
			omitOutgoingInterfaces: true,
			wantErr:                &tcpip.ErrMissingRequiredFields{},
		},
	}

	for _, test := range tests {
		for _, protocol := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
			t.Run(fmt.Sprintf("%s %s", test.name, getProtocolName(protocol)), func(t *testing.T) {
				s := stack.New(stack.Options{
					NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
					TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
				})
				defer s.Close()

				endpoints := make(map[tcpip.NICID]*channel.Endpoint)
				for nicID, addrType := range endpointConfigs {
					ep := channel.New(1, ipv4.MaxTotalSize, "")
					defer ep.Close()

					if err := s.CreateNIC(nicID, ep); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}
					addr := tcpip.ProtocolAddress{
						Protocol:          protocol,
						AddressWithPrefix: getEndpointAddr(protocol, addrType),
					}
					if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %#v, {}): %s", nicID, addr, err)
					}
					s.SetNICMulticastForwarding(nicID, protocol, true /* enabled */)
					endpoints[nicID] = ep
				}

				srcAddr := getAddr(protocol, test.srcAddr)
				dstAddr := getAddr(protocol, test.dstAddr)

				if test.injectPendingPacket {
					incomingEp, ok := endpoints[incomingNICID]
					if !ok {
						t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", incomingNICID)
					}

					injectPacket(incomingEp, protocol, srcAddr, dstAddr, packetTTL)
					p := incomingEp.Read()

					if p != nil {
						// An ICMP error should never be sent in response to a multicast packet.
						t.Fatalf("got incomingEp.Read() = %#v, want = nil", p)
					}
				}

				outgoingInterfaces := []stack.OutgoingInterface{
					{ID: test.routeOutgoingNICID, MinTTL: routeMinTTL},
				}
				if test.omitOutgoingInterfaces {
					outgoingInterfaces = nil
				}

				addresses := stack.UnicastSourceAndMulticastDestination{
					Source:      srcAddr,
					Destination: dstAddr,
				}
				route := stack.MulticastRoute{
					ExpectedInputInterface: test.routeIncomingNICID,
					OutgoingInterfaces:     outgoingInterfaces,
				}

				err := s.AddMulticastRoute(protocol, addresses, route)

				if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
					t.Errorf("got s.AddMulticastRoute(%d, %#v, %#v) = %s, want %s", protocol, addresses, route, err, test.wantErr)
				}

				outgoingEp, ok := endpoints[outgoingNICID]
				if !ok {
					t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
				}

				p := outgoingEp.Read()

				if (p != nil) != test.expectForward {
					t.Fatalf("got outgoingEp.Read() = %#v, want = (_ == nil) = %t", p, test.expectForward)
				}

				if test.expectForward {
					checkEchoRequest(t, protocol, p, srcAddr, dstAddr, packetTTL-1)
					p.DecRef()
				}
			})
		}
	}
}

func TestMulticastForwarding(t *testing.T) {
	endpointConfigs := map[tcpip.NICID]endpointAddrType{
		incomingNICID: incomingEndpointAddr,
		outgoingNICID: outgoingEndpointAddr,
		otherNICID:    otherEndpointAddr,
	}

	tests := []struct {
		name                                string
		dstAddr                             addrType
		ttl                                 uint8
		routeInputInterface                 tcpip.NICID
		disableMulticastForwarding          bool
		removeOutputInterface               bool
		expectForward                       bool
		expectMissingRouteEvent             bool
		expectUnexpectedInputInterfaceEvent bool
		joinMulticastGroup                  bool
	}{
		{
			name:                "forward only",
			dstAddr:             multicastAddr,
			ttl:                 packetTTL,
			routeInputInterface: incomingNICID,
			expectForward:       true,
		},
		{
			name:                "forward and local",
			dstAddr:             multicastAddr,
			ttl:                 packetTTL,
			routeInputInterface: incomingNICID,
			joinMulticastGroup:  true,
			expectForward:       true,
		},
		{
			name:                "local only",
			dstAddr:             linkLocalMulticastAddr,
			ttl:                 packetTTL,
			routeInputInterface: incomingNICID,
			joinMulticastGroup:  true,
		},
		{
			name:                       "multicast forwarding disabled",
			disableMulticastForwarding: true,
			dstAddr:                    multicastAddr,
			ttl:                        packetTTL,
			routeInputInterface:        incomingNICID,
		},
		{
			name:                                "unexpected input interface",
			dstAddr:                             multicastAddr,
			ttl:                                 packetTTL,
			routeInputInterface:                 otherNICID,
			expectUnexpectedInputInterfaceEvent: true,
		},
		{
			name:                  "output interface removed",
			dstAddr:               multicastAddr,
			ttl:                   packetTTL,
			routeInputInterface:   incomingNICID,
			removeOutputInterface: true,
		},
		{
			name:                "ttl same as route min",
			dstAddr:             multicastAddr,
			ttl:                 routeMinTTL,
			routeInputInterface: incomingNICID,
			expectForward:       true,
		},
		{
			name:                "ttl less than route min",
			dstAddr:             multicastAddr,
			ttl:                 routeMinTTL - 1,
			routeInputInterface: incomingNICID,
		},
		{
			name:                    "no matching route",
			dstAddr:                 otherMulticastAddr,
			ttl:                     packetTTL,
			routeInputInterface:     incomingNICID,
			expectMissingRouteEvent: true,
		},
	}

	for _, test := range tests {
		for _, protocol := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
			eventDispatcher := &multicastEventDispatcher{}
			t.Run(fmt.Sprintf("%s %s", test.name, getProtocolName(protocol)), func(t *testing.T) {
				s := stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocolFactory{
						ipv4.NewProtocolWithOptions(ipv4.Options{MulticastForwardingDisp: eventDispatcher}),
						ipv6.NewProtocolWithOptions(ipv6.Options{MulticastForwardingDisp: eventDispatcher}),
					},
					TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
				})
				defer s.Close()

				endpoints := make(map[tcpip.NICID]*channel.Endpoint)
				for nicID, addrType := range endpointConfigs {
					ep := channel.New(1, ipv4.MaxTotalSize, "")
					defer ep.Close()

					if err := s.CreateNIC(nicID, ep); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}
					addr := tcpip.ProtocolAddress{
						Protocol:          protocol,
						AddressWithPrefix: getEndpointAddr(protocol, addrType),
					}
					if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
					}

					s.SetNICMulticastForwarding(nicID, protocol, !test.disableMulticastForwarding)
					endpoints[nicID] = ep
				}

				if err := s.SetForwardingDefaultAndAllNICs(protocol, true /* enabled */); err != nil {
					t.Fatalf("SetForwardingDefaultAndAllNICs(%d, true): %s", protocol, err)
				}

				srcAddr := getAddr(protocol, remoteUnicastAddr)
				dstAddr := getAddr(protocol, test.dstAddr)

				outgoingInterfaces := []stack.OutgoingInterface{
					{ID: outgoingNICID, MinTTL: routeMinTTL},
				}
				addresses := stack.UnicastSourceAndMulticastDestination{
					Source:      srcAddr,
					Destination: getAddr(protocol, multicastAddr),
				}
				route := stack.MulticastRoute{
					ExpectedInputInterface: test.routeInputInterface,
					OutgoingInterfaces:     outgoingInterfaces,
				}

				if err := s.AddMulticastRoute(protocol, addresses, route); err != nil {
					t.Fatalf("AddMulticastRoute(%d, %#v, %#v): %s", protocol, addresses, route, err)
				}

				if test.removeOutputInterface {
					if err := s.RemoveNIC(outgoingNICID); err != nil {
						t.Fatalf("RemoveNIC(%d): %s", outgoingNICID, err)
					}
				}

				// Add a route that can be used to send an ICMP echo reply (if the packet
				// is delivered locally).
				s.SetRouteTable([]tcpip.Route{
					{
						Destination: header.IPv4EmptySubnet,
						NIC:         otherNICID,
					},
					{
						Destination: header.IPv6EmptySubnet,
						NIC:         otherNICID,
					},
				})

				if test.joinMulticastGroup {
					if err := s.JoinGroup(protocol, incomingNICID, dstAddr); err != nil {
						t.Fatalf("JoinGroup(%d, %d, %s): %s", protocol, incomingNICID, dstAddr, err)
					}
				}

				incomingEp, ok := endpoints[incomingNICID]
				if !ok {
					t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", incomingNICID)
				}

				injectPacket(incomingEp, protocol, srcAddr, dstAddr, test.ttl)
				p := incomingEp.Read()

				if p != nil {
					// An ICMP error should never be sent in response to a multicast packet.
					t.Fatalf("expected no ICMP packet through incoming NIC, instead found: %#v", p)
				}

				outgoingEp, ok := endpoints[outgoingNICID]
				if !ok {
					t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
				}

				p = outgoingEp.Read()

				if (p != nil) != test.expectForward {
					t.Fatalf("got outgoingEp.Read() = %#v, want = (_ == nil) = %t", p, test.expectForward)
				}

				if test.expectForward {
					checkEchoRequest(t, protocol, p, srcAddr, dstAddr, test.ttl-1)
					p.DecRef()
				}

				otherEp, ok := endpoints[otherNICID]
				if !ok {
					t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", otherNICID)
				}

				p = otherEp.Read()

				if (p != nil) != test.joinMulticastGroup {
					t.Fatalf("got otherEp.Read() = %#v, want = (_ == nil) = %t", p, test.joinMulticastGroup)
				}

				incomingEpAddrType, ok := endpointConfigs[incomingNICID]
				if !ok {
					t.Fatalf("got endpointConfigs[%d] = (_, false), want (_, true)", incomingNICID)
				}

				if test.joinMulticastGroup {
					checkEchoReply(t, protocol, p, getEndpointAddr(protocol, incomingEpAddrType).Address, srcAddr)
					p.DecRef()
				}

				wantUnexpectedInputInterfaceEvent := func() *onUnexpectedInputInterfaceData {
					if test.expectUnexpectedInputInterfaceEvent {
						return &onUnexpectedInputInterfaceData{stack.MulticastPacketContext{stack.UnicastSourceAndMulticastDestination{srcAddr, dstAddr}, incomingNICID}, test.routeInputInterface}
					}
					return nil
				}()

				if diff := cmp.Diff(wantUnexpectedInputInterfaceEvent, eventDispatcher.onUnexpectedInputInterfaceData, cmp.AllowUnexported(onUnexpectedInputInterfaceData{})); diff != "" {
					t.Errorf("onUnexpectedInputInterfaceData mismatch (-want +got):\n%s", diff)
				}

				wantMissingRouteEvent := func() *onMissingRouteData {
					if test.expectMissingRouteEvent {
						return &onMissingRouteData{stack.MulticastPacketContext{stack.UnicastSourceAndMulticastDestination{srcAddr, dstAddr}, incomingNICID}}
					}
					return nil
				}()

				if diff := cmp.Diff(wantMissingRouteEvent, eventDispatcher.onMissingRouteData, cmp.AllowUnexported(onMissingRouteData{})); diff != "" {
					t.Errorf("onMissingRouteData mismatch (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refsvfs2.DoLeakCheck()
	os.Exit(code)
}
