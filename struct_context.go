package main

import (
	aux "mt-aux"
	"mt-aux/dhcp"
	"mt-aux/maps"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
)

type ReqCtx struct {
	MAC    uint64
	MACStr string

	RelayIP       uint32
	RelayIPStr    string
	RelayIPSource int

	RemoteIP    uint32
	RemoteIPStr string

	LocalIP    uint32
	LocalIPStr string

	IP    uint32
	IPStr string

	DHCPRequest  dhcp.MessageType
	DHCPResponse dhcp.MessageType

	DropReason     string
	NAKReason      string
	NotFoundReason string
	LeaseSource    string

	Segment *Segment
	Subnet  *Subnet
	Lease   *Lease

	SegmentCopy *Segment
	SubnetCopy  *Subnet
	LeaseCopy   *Lease

	ReplyOptions   []dhcp.Option
	RequestOptions dhcp.Options

	Packet       *dhcp.Packet
	ReqLockShard *maps.ConcurrentMapUint64Shard

	RequestStart    time.Time
	RequestDuration time.Duration

	RequestSize  int
	ResponseSize int

	LogF log.Fields
}

func (c *ReqCtx) StatsInc(ID int) {
	if c.Segment != nil {
		c.Segment.Stats.Inc(ID)
	}

	if c.Subnet != nil {
		c.Subnet.Stats.Inc(ID)
	}
}

func (c *ReqCtx) StatsIncBy(By uint64, ID int) {
	if c.Segment != nil {
		c.Segment.Stats.IncBy(By, ID)
	}

	if c.Subnet != nil {
		c.Subnet.Stats.IncBy(By, ID)
	}
}

func (c *ReqCtx) FillLogFields() {
	c.LogF["mac"] = c.MACStr
	c.LogF["remote_ip"] = c.RemoteIPStr
	c.LogF["request"] = c.DHCPRequest.String()

	if c.DHCPResponse > 0 {
		c.LogF["response"] = c.DHCPResponse.String()
	}

	if c.RelayIP > 0 {
		c.LogF["relay_ip"] = c.RelayIPStr
	}

	if c.IP > 0 {
		c.LogF["ip"] = c.IPStr
	}

	if c.Segment != nil {
		c.LogF["segment"] = c.Segment.Name
		c.LogF["segment_id"] = c.Segment.Id
	}

	if c.Subnet != nil {
		c.LogF["subnet"] = c.Subnet.NetStr
	}

	if c.RequestDuration > 0 {
		c.LogF["duration"] = c.RequestDuration.String()
	}

	if c.Lease != nil {
		if c.Lease.Discover {
			c.LogF["tx_duration"] = int(c.Lease.TxDuration().Nanoseconds() / 1000)
		}

		if c.DHCPResponse == dhcp.ACK {
			c.LogF["ttl"] = int(c.Lease.ExpiresIn())
		}
	}

	if c.DropReason != "" {
		c.LogF["drop_reason"] = c.DropReason
	}

	if c.NAKReason != "" {
		c.LogF["nak_reason"] = c.NAKReason
	}

	if c.LeaseSource != "" {
		c.LogF["lease_source"] = c.LeaseSource
	}

	if c.NotFoundReason != "" {
		c.LogF["notfound_reason"] = c.NotFoundReason
	}
}

func (c *ReqCtx) LogErrorf(msg string, format ...interface{}) {
	c.FillLogFields()
	log.WithFields(c.LogF).Errorf(msg, format...)
}

func (c *ReqCtx) LogWarnf(msg string, format ...interface{}) {
	c.FillLogFields()
	log.WithFields(c.LogF).Warnf(msg, format...)
}

func (c *ReqCtx) LogInfof(msg string, format ...interface{}) {
	c.FillLogFields()
	log.WithFields(c.LogF).Infof(msg, format...)
}

func (c *ReqCtx) LogDebugf(msg string, format ...interface{}) {
	log.WithFields(c.LogF).Debugf(msg, format...)
}

func (c *ReqCtx) SetRequestedIP(IP uint32) {
	c.IP = IP
	c.IPStr = aux.IPIntToStr(IP)
}

func (c *ReqCtx) SetRelayIP(IP uint32) {
	c.RelayIP = IP
	c.RelayIPStr = aux.IPIntToStr(IP)
}

func (c *ReqCtx) SetLocalIP(IP net.IP) {
	c.LocalIP = aux.IPNetToInt(IP)
	c.LocalIPStr = IP.String()
}

func (c *ReqCtx) SetRemoteIP(IP net.IP) {
	c.RemoteIP = aux.IPNetToInt(IP)
	c.RemoteIPStr = IP.String()
}

func (c *ReqCtx) SegmentEvaluate() {
	var (
		ok, b bool
		err   error
		t     interface{}
	)

	p := map[string]interface{}{
		"RemoteIP": c.RemoteIP,
		"RelayIP":  c.RelayIP,
	}

	for _, v := range o.Segments {
		if t, err = v.DetectExpression.Evaluate(p); err != nil {
			c.LogErrorf("Unable to evaluate expression: %s", err)
			continue
		}

		if b, ok = t.(bool); !ok {
			c.LogErrorf("Expression result is not boolean")
			continue
		}

		if b {
			c.Segment = v
			c.SegmentCopy = &Segment{}
			*c.SegmentCopy = *c.Segment
			break
		}
	}
}

func (c *ReqCtx) ObtainRequestedIP() bool {
	// Obtain requested IP
	if ip := net.IP(c.RequestOptions[dhcp.OptionRequestedIPAddress]); ip != nil {
		c.SetRequestedIP(aux.IPNetToInt(ip))
		return true
	}

	// Option is not defined, check CIAddr
	if !c.Packet.CIAddr().Equal(net.IPv4zero) {
		c.SetRequestedIP(aux.IPNetToInt(c.Packet.CIAddr()))
		return true
	}

	// Request does not have valid OptionRequestedIPAddress, nor CIAddr, drop packet
	// This seem to happen with some noname China-phones - they usually fall back to DISCOVER after timeout and get IP successfully then
	return false
}

// Searches for subnet or creates it (if auto mode is enabled)
func (c *ReqCtx) ObtainSubnet() {
	var ok bool
	c.LogDebugf("Searching subnet for %s", c.RelayIPStr)

	c.Segment.RLock()
	// Iterate through all different masks, apply them and check if it matches any configured subnet
	for _, Mask := range c.Segment.Masks {
		c.LogDebugf("Checking mask %s -> subnet %s", aux.IPIntToStr(Mask), aux.IPIntToStr(c.RelayIP&Mask))

		// Check if subnet exists
		if c.Subnet, ok = c.Segment.Subnets[c.RelayIP&Mask]; !ok {
			continue
		}

		// Check if this subnet has the same mask
		if c.Subnet.Mask == Mask {
			break
		}

		c.Subnet = nil
	}
	c.Segment.RUnlock()

	if c.Subnet != nil {
		goto out
	}

	c.LogDebugf("No subnet found")

	if !c.Segment.AutoMode {
		return
	}

	c.LogDebugf("Auto mode - constructing subnet")

	// Generate subnet
	c.Subnet = GenerateAutoSubnet(c.RelayIP&c.Segment.AutoModeMask, c.Segment)

	// Cache created subnet - map lookup with mutex is ~40-60x faster than dynamically creating subnet on each request
	c.Segment.Lock()
	c.Segment.Subnets[c.Subnet.Net] = c.Subnet
	c.Segment.Unlock()

	if err := SubnetUploadToAerospike(c.Subnet, c.Segment); err != nil {
		c.LogErrorf("Unable to upload subnet to Aerospike: %s", err)
	}

	c.LogDebugf("Auto-Subnet %s generated (Range: %s - %s, Router: %s, Lease TTL: %s)",
		c.Subnet.NetStr,
		aux.IPIntToStr(c.Subnet.RangeStart),
		aux.IPIntToStr(c.Subnet.RangeEnd),
		aux.IPIntToStr(c.Subnet.Net+c.Segment.AutoModeRouter),
		c.Subnet.LeaseTTL,
	)

out:
	c.SubnetCopy = &Subnet{}
	*c.SubnetCopy = *c.Subnet
}

// Add DNS servers
func (c *ReqCtx) AddDNS() {
	var DNS []net.IP

	if c.Subnet.Dynamic {
		DNS = make([]net.IP, len(c.Segment.AutoModeDNS))
		copy(DNS, c.Segment.AutoModeDNS)
	} else {
		DNS = make([]net.IP, len(c.Subnet.DNS))
		copy(DNS, c.Subnet.DNS)
	}

	if c.Segment.DNSRandom {
		aux.ShuffleNetIPSlice(DNS)
	}

	c.LogDebugf("Using DNS: %+v", DNS)

	for _, d := range DNS {
		c.ReplyOptions = append(c.ReplyOptions, dhcp.Option{
			Code:  dhcp.OptionDomainNameServer,
			Value: d.To4(),
		})
	}
}

func (c *ReqCtx) WorkStart() (ok bool) {
	c.ReqLockShard = RequestLock.GetShard(c.MAC)

	c.ReqLockShard.Lock()
	if _, ok = c.ReqLockShard.Items[c.MAC].(bool); !ok {
		c.ReqLockShard.Items[c.MAC] = true
	}
	c.ReqLockShard.Unlock()

	return !ok
}

func (c *ReqCtx) WorkFinish() {
	if c.ReqLockShard == nil {
		return
	}

	c.ReqLockShard.Lock()
	delete(c.ReqLockShard.Items, c.MAC)
	c.ReqLockShard.Unlock()
}

func (c *ReqCtx) GenerateReply(Response dhcp.MessageType) (Reply dhcp.Packet) {
	c.RequestDuration = time.Since(c.RequestStart)
	c.DHCPResponse = Response

	switch c.DHCPResponse {
	case dhcp.Offer:
		c.StatsInc(STATS_REPLIES_OFFER)

		Reply = dhcp.ReplyPacket(
			*c.Packet, dhcp.Offer, aux.IPIntToNet(c.LocalIP).To4(), aux.IPIntToNet(c.IP).To4(),
			c.Subnet.LeaseTTL, append(c.ReplyOptions, c.Subnet.DHCPOptions...),
		)

	case dhcp.ACK:
		c.StatsInc(STATS_REPLIES_ACK)

		Reply = dhcp.ReplyPacket(
			*c.Packet, dhcp.ACK, aux.IPIntToNet(c.LocalIP).To4(), aux.IPIntToNet(c.IP).To4(),
			c.Subnet.LeaseTTL, append(c.ReplyOptions, c.Subnet.DHCPOptions...),
		)

	case dhcp.NAK:
		c.StatsInc(STATS_REPLIES_NAK)

		Reply = dhcp.ReplyPacket(
			*c.Packet, dhcp.NAK, aux.IPIntToNet(c.LocalIP).To4(), nil, 0, nil,
		)

	case dhcp.Drop:
		c.StatsInc(STATS_REPLIES_DROP)
		Reply = nil

	default:
		log.Errorf("Unknown dhcp.MessageType: %d", c.DHCPResponse)
		Reply = nil
	}

	if Reply != nil {
		c.ResponseSize = len(Reply)
		c.StatsIncBy(uint64(c.ResponseSize), STATS_BYTES_OUT)
		c.StatsInc(STATS_PACKETS_OUT)
	}

	c.WorkFinish()

	go MetricsSendDHCPRequest(c)
	c.LogInfof("")
	return Reply
}
