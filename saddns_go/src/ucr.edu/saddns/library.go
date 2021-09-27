package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

func GetIfaceAddrMulti(iface *net.Interface) ([]net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, errors.New("can not get ip address")
	}

	var srcIP []net.IP
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				//check repeat
				okToAdd := true
				for _, temp := range srcIP {
					if compareIPv4Addr(temp, ipnet.IP.To4()) == 0 {
						okToAdd = false
						break
					}
				}
				if okToAdd {
					srcIP = append(srcIP, ipnet.IP.To4())
				}
			}
		}
	}

	if srcIP == nil || len(srcIP) == 0 {
		return nil, errors.New("can not get ip address")
	}

	return srcIP, nil
}

func Send(handle *pcap.Handle, l ...gopacket.SerializableLayer) error {
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, opts, l...); err != nil {
		return err
	}
	return handle.WritePacketData(buffer.Bytes())
}

func GetIfaceAddr(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, errors.New("can not get ip address")
	}

	var srcIP net.IP
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				srcIP = ipnet.IP.To4()
				break
			}
		}
	}

	if srcIP == nil {
		return nil, errors.New("can not get ip address")
	}

	return srcIP, nil
}

func GetGatewayAddr(iface *net.Interface, handle *pcap.Handle, gatewayIP net.IP) (net.HardwareAddr, error) {
	srcIP, err := GetIfaceAddr(iface)
	if err != nil {
		return nil, errors.New("can not get ip address")
	}

	start := time.Now()
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(gatewayIP),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	if err := Send(handle, &eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(gatewayIP) {
				return arp.SourceHwAddress, nil
			}
		}
	}
}

func compareIPv4Addr(ip0 net.IP, ip1 net.IP) int {
	temp0 := binary.LittleEndian.Uint32(ip0.To4())
	temp1 := binary.LittleEndian.Uint32(ip1.To4())
	if temp0 == temp1 {
		return 0
	}
	if temp0 > temp1 {
		return 1
	}
	return -1
}

func xmitUDPv4(srcIP net.IP, dstIP net.IP, srcPort layers.UDPPort, dstPort layers.UDPPort, ipid uint16, timegap uint32) {

	ipLayer := layers.IPv4{
		Id:       ipid,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	err := udpLayer.SetNetworkLayerForChecksum(&ipLayer)
	if err != nil {
		fmt.Println("xmitUDPv4 can not SetNetworkLayerForChecksum", err)
	}
	err = Send(handle, ethernetLayer, &ipLayer, &udpLayer)
	if err != nil {
		fmt.Println("xmitUDPv4 can not send packet", err)
	}

	if timegap != 0 {
		time.Sleep(time.Duration(timegap) * time.Microsecond)
	}

}
