package main

import (
	aux "mt-aux"
	dhcp "mt-aux/dhcp"
	"mt-aux/maps"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
)

const (
	LEASE_SRC_EXISTING = "Existing"
	LEASE_SRC_RANDOM   = "Random"
	LEASE_SRC_RANGE    = "Range"
)

const (
	NOTFOUND_NOTFOUND    = "NotFound"
	NOTFOUND_EXPIRED     = "Expired"
	NOTFOUND_ANOTHER_MAC = "AnotherMAC"
)

const (
	DROPREASON_MALFORMED_PACKET    = "MalformedPacket"
	DROPREASON_RELAYIP_NOT_FOUND   = "RelayIPNotFound"
	DROPREASON_UNKNOWN_SEGMENT     = "UnknownSegment"
	DROPREASON_CONCURRENT_REQUEST  = "ConcurrentRequest"
	DROPREASON_BACKEND_ERROR       = "BackendError"
	DROPREASON_NO_FREE_LEASES      = "NoFreeLeases"
	DROPREASON_INCORRECT_SERVER    = "IncorrectServer"
	DROPREASON_NO_REQUESTED_IP     = "NoRequestedIP"
	DROPREASON_UNSUPPORTED_REQUEST = "UnsupportedRequest"
)

var (
	DHCPBackend Backend
	RequestLock maps.ConcurrentMapUint64
)

// Main worker function - handles incoming DHCP packets
func DHCPHandleRequest(p dhcp.Packet, msgType dhcp.MessageType, options dhcp.Options, LocalAddr net.IP, RemoteAddr net.IP) (d dhcp.Packet) {
	var err error

	// Pause if cache reloading is in progress
	CacheReloadingMtx.RLock()
	defer CacheReloadingMtx.RUnlock()

	// Initialize request context
	Ctx := &ReqCtx{
		RequestStart: time.Now(),
		LogF:         log.Fields{},

		MAC: aux.MACByteToInt(p.CHAddr()),

		RelayIPStr: "?.?.?.?",

		DHCPRequest: msgType,

		RequestOptions: options,
		Packet:         &p,

		RequestSize: len(p),
	}
	Ctx.MACStr = aux.MACIntToStr(Ctx.MAC)

	Ctx.SetRemoteIP(RemoteAddr)
	Ctx.SetLocalIP(LocalAddr)

	// Check if there's an Option-82 defined and parse if it is
	var (
		Option82Raw   []byte
		Option82      map[uint8][]byte
		LinkSelection []byte
	)

	if Option82Raw = options[dhcp.OptionRelayAgentInformation]; Option82Raw == nil {
		goto Option82Done
	}

	Option82 = dhcp.ParseOption82(Option82Raw)
	// Check if there's an Link-Selection sub-option
	if LinkSelection = Option82[dhcp.Option82LinkSelection]; LinkSelection == nil {
		Ctx.LogWarnf("No Link-Selection suboption in Option-82 found")
		goto Option82Done
	}

	// It should be 4 bytes (as it's an IP address)
	if len(LinkSelection) == 4 {
		Ctx.SetRelayIP(aux.IPByteToInt(LinkSelection))
		Ctx.LogDebugf("Got Relay IP from Option-82: %s", Ctx.RelayIPStr)
		Ctx.RelayIPSource = STATS_RELAYIP_OPTION82
		goto RelayIPObtained
	}

	// If it's not - then the packet is broken, don't process it
	Ctx.LogWarnf("Wrong Option82 [Link-Selection] length %d != 4", len(LinkSelection))
	Stats.Inc(STATS_ERRORS_MALFORMED_PACKET)
	Ctx.DropReason = DROPREASON_MALFORMED_PACKET
	goto Drop

Option82Done:
	// We still don't have RelayIP, try to obtain it by other means

	// Get Relay IP from GIAddr
	if Ctx.SetRelayIP(aux.IPNetToInt(p.GIAddr())); Ctx.RelayIP > 0 {
		// Successfully got RelayIP from giaddr
		Ctx.RelayIPSource = STATS_RELAYIP_GIADDR
		goto RelayIPObtained
	}

	// This is the case when client directly talks unicast to DHCP server
	if msgType != dhcp.Request {
		Ctx.LogWarnf("Cannot obtain requested IP")
		Stats.Inc(STATS_ERRORS_RELAYIP_NOT_FOUND)
		Ctx.DropReason = DROPREASON_RELAYIP_NOT_FOUND
		goto Drop
	}

	if Ctx.ObtainRequestedIP() {
		// Check if client's source address match the address requested
		if Ctx.IP == Ctx.RemoteIP {
			Ctx.SetRelayIP(Ctx.IP)
			Ctx.RelayIPSource = STATS_RELAYIP_UNICAST
			goto RelayIPObtained
		}

		Ctx.LogWarnf("Requested IP (%s) does not match RemoteAddr (%s)", aux.IPIntToStr(Ctx.IP), aux.IPIntToStr(Ctx.RemoteIP))
		Stats.Inc(STATS_ERRORS_RELAYIP_NOT_FOUND)
		Ctx.DropReason = DROPREASON_RELAYIP_NOT_FOUND
		goto Drop
	}

RelayIPObtained:
	// Drop packets with zero MAC
	if Ctx.MAC == 0 {
		Ctx.LogWarnf("MAC is zero, dropping request")
		Stats.Inc(STATS_ERRORS_MALFORMED_PACKET)
		Ctx.DropReason = DROPREASON_MALFORMED_PACKET
		goto Drop
	}

	// Drop request if segment wasn't detected
	if Ctx.SegmentEvaluate(); Ctx.Segment == nil {
		Ctx.LogWarnf("Unable to detect segment, dropping request")
		Stats.Inc(STATS_ERRORS_UNKNOWN_SEGMENT)
		Ctx.DropReason = DROPREASON_UNKNOWN_SEGMENT
		goto Drop
	}

	Ctx.FillLogFields()
	Ctx.LogDebugf("Segment '%s' detected", Ctx.Segment.Name)

	// Find subnet
	if Ctx.ObtainSubnet(); Ctx.Subnet == nil {
		Ctx.LogWarnf("Relay IP '%s' does not belong to any configured subnet, dropping request", Ctx.RelayIPStr)
		Stats.Inc(STATS_ERRORS_UNKNOWN_SUBNET)
		goto Drop
	}

	Ctx.StatsInc(STATS_REQUESTS_TOTAL)
	Ctx.StatsInc(STATS_PACKETS_IN)
	Ctx.StatsIncBy(uint64(Ctx.RequestSize), STATS_BYTES_IN)
	Ctx.StatsInc(Ctx.RelayIPSource)
	Ctx.LogDebugf("Subnet detected: %s", Ctx.Subnet.NetStr)

	// Check if we're already working on a request for this MAC
	if !Ctx.WorkStart() {
		Ctx.LogDebugf("Already working on request for this MAC, dropping")
		Ctx.StatsInc(STATS_ERRORS_CONCURRENT)
		Ctx.DropReason = DROPREASON_CONCURRENT_REQUEST
		goto Drop
	}

	switch msgType {
	case dhcp.Discover:
		Ctx.StatsInc(STATS_REQUESTS_DISCOVER)

		// Look for an existing valid lease for this subnet + mac combination or get a new lease
		if err = DHCPBackend.LeaseFind(Ctx); err != nil {
			Ctx.LogErrorf("Error searching for leases: %s", err)
			Ctx.DropReason = DROPREASON_BACKEND_ERROR
			break
		}

		if Ctx.IP == 0 {
			Ctx.LogWarnf("No free leases found")
			Ctx.DropReason = DROPREASON_NO_FREE_LEASES
			break
		}

		Ctx.AddDNS()
		Ctx.LogDebugf("Offering address: %s", Ctx.IPStr)
		return Ctx.GenerateReply(dhcp.Offer)

	case dhcp.Request:
		Ctx.StatsInc(STATS_REQUESTS_REQUEST)

		// If ServerID is defined and it does not match our IP - drop the packet
		if ServerID, ok := options[dhcp.OptionServerIdentifier]; ok && !net.IP(ServerID).Equal(LocalAddr) {
			Ctx.LogWarnf("ServerID '%s' != '%s', dropping request", net.IP(ServerID).String(), LocalAddr.String())
			Ctx.StatsInc(STATS_ERRORS_INCORRECT_SERVER)
			Ctx.DropReason = DROPREASON_INCORRECT_SERVER
			break
		}

		if !Ctx.ObtainRequestedIP() {
			Ctx.LogInfof("Packet does not have RequestedIP option, nor client IP, dropping")
			Ctx.StatsInc(STATS_ERRORS_NO_REQUESTED_IP)
			Ctx.DropReason = DROPREASON_NO_REQUESTED_IP
			break
		}

		Ctx.LogDebugf("Requested IP: %s", Ctx.IPStr)

		// Check if requested ip belongs to subnet where the request came from
		// It's normal for clients to REQUEST their old IPs from other subnet, we should NAK such requests
		if (Ctx.IP & Ctx.Subnet.Mask) != Ctx.Subnet.Net {
			Ctx.LogDebugf("Requested IP (%s) does not match subnet (%s), NAK", Ctx.IPStr, Ctx.Subnet.NetStr)
			Ctx.NAKReason = "IPSubnetMismatch"
			return Ctx.GenerateReply(dhcp.NAK)
		}

		// Try to fetch MAC from client's lease created on DISCOVER stage (or on previous REQUEST - renewal) and compare it to client's MAC
		if err = DHCPBackend.LeaseCheckAndUpdate(Ctx); err != nil {
			Ctx.LogErrorf("Error updating lease: %s", err)
			Ctx.DropReason = DROPREASON_BACKEND_ERROR
			break
		}

		if Ctx.Lease == nil {
			Ctx.NAKReason = "LeaseNotFound"
			return Ctx.GenerateReply(dhcp.NAK)
		}

		Ctx.LogDebugf("ACKing lease: %s", Ctx.IPStr)
		Ctx.AddDNS()
		return Ctx.GenerateReply(dhcp.ACK)

	case dhcp.Release:
		Ctx.StatsInc(STATS_REQUESTS_RELEASE)

		// Check for valid CIAddr
		if p.CIAddr().Equal(net.IPv4zero) {
			Ctx.LogWarnf("Packet does not have valid client IP, dropping")
			Ctx.StatsInc(STATS_ERRORS_NO_REQUESTED_IP)
			Ctx.DropReason = DROPREASON_NO_REQUESTED_IP
			break
		}

		Ctx.SetRequestedIP(aux.IPNetToInt(p.CIAddr()))

		// Delete lease if client's MAC matches lease's MAC
		DHCPBackend.LeaseCheckAndDelete(Ctx)

		return Ctx.GenerateReply(dhcp.Drop)

	case dhcp.Decline:
		Ctx.StatsInc(STATS_REQUESTS_DECLINE)

		// Check for valid requested_ip
		if net.IP(options[dhcp.OptionRequestedIPAddress]) == nil {
			Ctx.LogWarnf("Packet does not have valid requested IP, dropping")
			Ctx.StatsInc(STATS_ERRORS_NO_REQUESTED_IP)
			Ctx.DropReason = DROPREASON_NO_REQUESTED_IP
			break
		}

		Ctx.SetRequestedIP(aux.IPNetToInt(net.IP(options[dhcp.OptionRequestedIPAddress])))

		// Delete lease if client's MAC matches lease's MAC
		DHCPBackend.LeaseCheckAndDelete(Ctx)
		break

	case dhcp.Inform:
		Ctx.StatsInc(STATS_REQUESTS_INFORM)

		Ctx.LogDebugf("ACKing INFORM")
		Ctx.AddDNS()
		Ctx.WorkFinish()

		return Ctx.GenerateReply(dhcp.ACK)

	default:
		Ctx.StatsInc(STATS_ERRORS_OTHER)
		Ctx.LogWarnf("Unsupported DHCP packet type '%s', dropping request", msgType.String())
		Ctx.DropReason = DROPREASON_UNSUPPORTED_REQUEST
	}

Drop:
	return Ctx.GenerateReply(dhcp.Drop)
}

// Gets & parses DHCP packets from buffer and dispatches them to work
func DHCPHandleConnection(Conn *net.UDPConn, Buffer []byte, RemoteAddr *net.UDPAddr, LocalAddr net.IP) {
	var (
		RequestType dhcp.MessageType
		n           int
		err         error
	)

	Packet := dhcp.Packet(Buffer)

	// Invalid size
	if Packet.HLen() != 6 {
		Stats.Inc(STATS_ERRORS_MALFORMED_PACKET)
		log.Warnf("Malformed packet (req.HLEN != 6) from %s", RemoteAddr.IP.String())
		return
	}

	options := Packet.ParseOptions()
	if t := options[dhcp.OptionDHCPMessageType]; len(t) != 1 {
		// These are usually BOOTP requests from misconfigured Apple devices
		Stats.Inc(STATS_ERRORS_MALFORMED_PACKET)
		log.Debugf("Malformed packet (len(DHCPMessageType) != 1) from '%s' (MAC %s)", RemoteAddr.IP.String(), Packet.CHAddr().String())
		return
	} else {
		RequestType = dhcp.MessageType(t[0])
	}

	// Unknown request type
	if RequestType < dhcp.Discover || RequestType > dhcp.Inform {
		Stats.Inc(STATS_ERRORS_MALFORMED_PACKET)
		log.Warnf("Unknown DHCPMessageType %d from %s", RequestType, RemoteAddr.IP.String())
		return
	}

	// Process DHCP request
	if res := DHCPHandleRequest(Packet, RequestType, options, LocalAddr, RemoteAddr.IP); res != nil {
		if n, err = Conn.WriteToUDP(res, RemoteAddr); err != nil {
			Stats.Inc(STATS_ERRORS_OTHER)
			log.Errorf("Unable to send packet to %s, error: %s", RemoteAddr.IP.String(), err)
			return
		}

		Stats.Inc(STATS_PACKETS_OUT)
		Stats.IncBy(uint64(n), STATS_BYTES_OUT)
	}

	return
}

func init() {
	RequestLock = maps.NewConcurrentMapUint64()
}

// Initializes DHCP socket and handles requests
func DHCPServe(LocalAddr net.IP) {
	var (
		RemoteAddr *net.UDPAddr
		Conn       *net.UDPConn

		n   int
		err error
	)

	if Conn, err = net.ListenUDP("udp4", &net.UDPAddr{
		IP:   LocalAddr,
		Port: 67,
	}); err != nil {
		log.Fatalf("ListenUDP error: %s", err)
	}

	log.Warnf("Listening to %s", LocalAddr.String())

	// Set I/O buffers to handle traffic spikes
	Conn.SetReadBuffer(o.DHCPBufferSize)
	Conn.SetWriteBuffer(o.DHCPBufferSize)

	// Main working loop: receives DHCP packets and dispatches them to goroutines for processing
	for {
		// It seems that DHCP packets cannot be larger than 576 bytes
		Buffer := make([]byte, 576)
		n, RemoteAddr, err = Conn.ReadFromUDP(Buffer)
		Stats.Inc(STATS_REQUESTS_TOTAL)
		Stats.Inc(STATS_PACKETS_IN)
		Stats.IncBy(uint64(n), STATS_BYTES_IN)

		// Abort if error and it's not temporary
		if err != nil {
			if !err.(*net.OpError).Temporary() {
				log.Errorf("Fatal ReadFromUDP() error: %s", err)
				break
			} else {
				log.Warnf("Temporary ReadFromUDP() error: %s", err)
				Stats.Inc(STATS_ERRORS_OTHER)
				continue
			}
		}

		// Skip too small packets
		if n < 240 {
			Stats.Inc(STATS_ERRORS_MALFORMED_PACKET)
			log.Warnf("Packet from %s is too small to be DHCP (%d bytes) - dropping", RemoteAddr.IP.String(), n)
			continue
		}

		// Dispatch work to goroutine
		Buffer = Buffer[:n]
		go DHCPHandleConnection(Conn, Buffer, RemoteAddr, LocalAddr)
	}
}
