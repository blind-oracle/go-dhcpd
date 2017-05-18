package main

import (
	"math"
	"mt-aux/dhcp"
	"mt-aux/metrics"
	"net"
	"sync"
	"time"

	"github.com/Knetic/govaluate"
)

type Lease struct {
	IP           uint32
	MAC          uint64
	Expires      time.Time
	Discover     bool
	DiscoverTime time.Time
}

func (l *Lease) Expired() bool {
	return time.Now().After(l.Expires)
}

func (l *Lease) ExpiresIn() (Seconds int) {
	return int(math.Ceil(l.Expires.Sub(time.Now()).Seconds()))
}

func (l *Lease) DiscoverSet() {
	l.Discover = true
	l.DiscoverTime = time.Now()
}

func (l *Lease) TxDuration() time.Duration {
	return time.Since(l.DiscoverTime)
}

type Subnet struct {
	Dynamic bool

	Net        uint32
	NetStr     string
	Mask       uint32
	RangeStart uint32
	RangeEnd   uint32
	Router     uint32
	LeaseTTL   time.Duration

	DNS    []net.IP
	DNSStr []string

	DHCPOptions []dhcp.Option

	LeasesByIP  map[uint32]*Lease
	LeasesByMAC map[uint64]*Lease

	LeasesActiveCount  int
	LeasesExpiredCount int

	Stats *metrics.Stats
	sync.RWMutex
}

func (s *Subnet) Capacity() int {
	return int(s.RangeEnd) - int(s.RangeStart) + 1
}

func (s *Subnet) LeasesActive() int {
	s.RLock()
	defer s.RUnlock()
	return s.LeasesActiveCount
}

func (s *Subnet) LeasesExpired() int {
	s.RLock()
	defer s.RUnlock()
	return s.LeasesExpiredCount
}

func (s *Subnet) UpdateStats() {
	s.Lock()
	s.UpdateStatsNoLock()
	s.Unlock()
}

func (s *Subnet) UpdateStatsNoLock() {
	s.LeasesActiveCount = 0
	s.LeasesExpiredCount = 0
	for _, Lease := range s.LeasesByIP {
		if Lease.Expired() {
			s.LeasesExpiredCount++
		} else {
			s.LeasesActiveCount++
		}
	}
}

func (s *Subnet) CleanupExpired() (ExpiredMAC, ExpiredIP int) {
	var (
		Lease *Lease
		ok    bool
	)

	s.Lock()
	for mac, l := range s.LeasesByMAC {
		if time.Since(l.Expires) > o.DHCPCleanupAge {
			ExpiredMAC++
			delete(s.LeasesByMAC, mac)

			// Check if the corresponding lease is in LeasesByIP and delete it also
			if Lease, ok = s.LeasesByIP[l.IP]; ok && Lease.MAC == l.MAC {
				ExpiredIP++
				delete(s.LeasesByIP, l.IP)
			}
		}
	}
	s.Unlock()

	return
}

func (s *Subnet) StatsInit() {
	s.Stats = &metrics.Stats{
		Items: StatsSubnet,
	}

	s.Stats.Init()
}

type Segment struct {
	Id   int
	Name string

	DetectRule       string
	DetectExpression *govaluate.EvaluableExpression

	DNSRandom bool

	AutoMode           bool
	AutoModeMask       uint32
	AutoModeRangeStart uint32
	AutoModeRangeEnd   uint32
	AutoModeRouter     uint32
	AutoModeDNS        []net.IP
	AutoModeLeaseTTL   time.Duration

	Subnets map[uint32]*Subnet
	Masks   []uint32

	LeasesTotal   int
	LeasesActive  int
	LeasesExpired int

	Stats *metrics.Stats
	sync.RWMutex
}

func (s *Segment) StatsInit() {
	s.Stats = &metrics.Stats{
		Items: StatsSubnet,
	}

	s.Stats.Init()
}

func (s *Segment) DeleteDynamicSubnets() {
	s.Lock()
	for NetAddr, Subnet := range s.Subnets {
		if Subnet.Dynamic {
			delete(s.Subnets, NetAddr)
		}
	}
	s.Unlock()
}
