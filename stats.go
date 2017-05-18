package main

import (
	"bytes"
	"fmt"
	aux "mt-aux"
	"mt-aux/metrics"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

type StatsSegmentsStruct struct {
	GenerationTime string                         `json:"generation_time"`
	Segments       map[string]*StatsSegmentStruct `json:"segments"`
}

type StatsSegmentStruct struct {
	Name string `json:"name"`

	Capacity      int `json:"capacity"`
	LeasesActive  int `json:"leases_active"`
	LeasesExpired int `json:"leases_expired"`

	Stats   map[string]uint64             `json:"stats"`
	Subnets map[string]*StatsSubnetStruct `json:"subnets"`
}

type StatsSubnetStruct struct {
	Subnet string `json:"subnet"`

	Capacity      int `json:"capacity"`
	LeasesActive  int `json:"leases_active"`
	LeasesExpired int `json:"leases_expired"`

	Stats map[string]uint64 `json:"stats"`
}

const (
	STATS_REQUESTS_TOTAL = iota

	STATS_REQUESTS_DISCOVER
	STATS_REQUESTS_REQUEST
	STATS_REQUESTS_RELEASE
	STATS_REQUESTS_DECLINE
	STATS_REQUESTS_INFORM

	STATS_REPLIES_OFFER
	STATS_REPLIES_ACK
	STATS_REPLIES_NAK
	STATS_REPLIES_DROP

	STATS_RELAYIP_OPTION82
	STATS_RELAYIP_GIADDR
	STATS_RELAYIP_UNICAST

	STATS_LEASE_EXISTING
	STATS_LEASE_RANDOM
	STATS_LEASE_RANGE
	STATS_LEASE_NO_FREE

	STATS_ERRORS_RELAYIP_NOT_FOUND
	STATS_ERRORS_MALFORMED_PACKET
	STATS_ERRORS_UNKNOWN_SEGMENT
	STATS_ERRORS_UNKNOWN_SUBNET
	STATS_ERRORS_INCORRECT_SERVER
	STATS_ERRORS_NO_REQUESTED_IP
	STATS_ERRORS_CONCURRENT
	STATS_ERRORS_OTHER

	STATS_PACKETS_IN
	STATS_PACKETS_OUT
	STATS_BYTES_IN
	STATS_BYTES_OUT
)

var (
	StatsGlobal = map[int]*metrics.Item{
		STATS_REQUESTS_TOTAL: &metrics.Item{
			Description: "Requests [Total]",
		},

		STATS_ERRORS_RELAYIP_NOT_FOUND: &metrics.Item{
			Description: "Errors [RelayIP Not Found]",
		},
		STATS_ERRORS_MALFORMED_PACKET: &metrics.Item{
			Description: "Errors [Malformed Packet]",
		},
		STATS_ERRORS_UNKNOWN_SEGMENT: &metrics.Item{
			Description: "Errors [Unknown Segment]",
		},
		STATS_ERRORS_UNKNOWN_SUBNET: &metrics.Item{
			Description: "Errors [Unknown Subnet]",
		},
		STATS_ERRORS_OTHER: &metrics.Item{
			Description: "Errors [Other]",
		},

		STATS_PACKETS_IN: &metrics.Item{
			Description: "Packets [In]",
		},
		STATS_PACKETS_OUT: &metrics.Item{
			Description: "Packets [Out]",
		},

		STATS_BYTES_IN: &metrics.Item{
			Description: "Bytes [In]",
		},
		STATS_BYTES_OUT: &metrics.Item{
			Description: "Bytes [Out]",
		},
	}

	StatsSubnet = map[int]*metrics.Item{
		STATS_REQUESTS_TOTAL: &metrics.Item{
			Description: "Requests [Total]",
		},

		STATS_REQUESTS_DISCOVER: &metrics.Item{
			Description: "Requests [Discover]",
		},
		STATS_REQUESTS_REQUEST: &metrics.Item{
			Description: "Requests [Request]",
		},
		STATS_REQUESTS_RELEASE: &metrics.Item{
			Description: "Requests [Release]",
		},
		STATS_REQUESTS_DECLINE: &metrics.Item{
			Description: "Requests [Decline]",
		},
		STATS_REQUESTS_INFORM: &metrics.Item{
			Description: "Requests [Inform]",
		},

		STATS_REPLIES_OFFER: &metrics.Item{
			Description: "Replies [Offer]",
		},
		STATS_REPLIES_ACK: &metrics.Item{
			Description: "Replies [ACK]",
		},
		STATS_REPLIES_NAK: &metrics.Item{
			Description: "Replies [NAK]",
		},
		STATS_REPLIES_DROP: &metrics.Item{
			Description: "Replies [Drop]",
		},

		STATS_RELAYIP_OPTION82: &metrics.Item{
			Description: "Relay IP Source [Option-82]",
		},
		STATS_RELAYIP_GIADDR: &metrics.Item{
			Description: "Relay IP Source [GIAddr]",
		},
		STATS_RELAYIP_UNICAST: &metrics.Item{
			Description: "Relay IP Source [Unicast]",
		},

		STATS_LEASE_EXISTING: &metrics.Item{
			Description: "Lease [Existing]",
		},
		STATS_LEASE_RANDOM: &metrics.Item{
			Description: "Lease [Random]",
		},
		STATS_LEASE_RANGE: &metrics.Item{
			Description: "Lease [Range]",
		},
		STATS_LEASE_NO_FREE: &metrics.Item{
			Description: "Lease [No Free]",
		},

		STATS_ERRORS_CONCURRENT: &metrics.Item{
			Description: "Errors [Concurrent Requests]",
		},
		STATS_ERRORS_INCORRECT_SERVER: &metrics.Item{
			Description: "Errors [Incorrect ServerID]",
		},
		STATS_ERRORS_NO_REQUESTED_IP: &metrics.Item{
			Description: "Errors [No RequestedIP]",
		},
		STATS_ERRORS_OTHER: &metrics.Item{
			Description: "Errors [Other]",
		},

		STATS_PACKETS_IN: &metrics.Item{
			Description: "Packets [In]",
		},
		STATS_PACKETS_OUT: &metrics.Item{
			Description: "Packets [Out]",
		},

		STATS_BYTES_IN: &metrics.Item{
			Description: "Bytes [In]",
		},
		STATS_BYTES_OUT: &metrics.Item{
			Description: "Bytes [Out]",
		},
	}
)

func init() {
	Stats = &metrics.Stats{
		Items: StatsGlobal,
	}

	Stats.Init()
}

func StatsDumpGlobal() (s string) {
	s += StatsHeader()
	s += "Global statistics:\n"

	for _, r := range strings.Split(Stats.Dump(), "\n") {
		s += fmt.Sprintf(" %s\n", r)
	}

	return
}

func StatsDumpSegments() (s string) {
	var (
		Segments                  []int
		Capacity, Active, Expired int
	)

	for S := range o.Segments {
		Segments = append(Segments, S)
	}
	sort.Ints(Segments)

	s += StatsHeader()

	for _, S := range Segments {
		Capacity, Active, Expired = 0, 0, 0
		Seg := o.Segments[S]

		Seg.RLock()
		for _, Net := range Seg.Subnets {
			Net.RLock()
			Capacity += Net.Capacity()
			Active += Net.LeasesActive()
			Expired += Net.LeasesExpired()
			Net.RUnlock()
		}

		s += fmt.Sprintf("Segment '%s' statistics (%d subnets, %d/%d/%d leases total/active/expired):\n",
			Seg.Name, len(Seg.Subnets), Capacity, Active, Expired)

		Seg.RUnlock()

		for _, r := range strings.Split(Seg.Stats.Dump(), "\n") {
			s += fmt.Sprintf(" %s\n", r)
		}
	}

	return
}

func StatsDumpSubnets() (s string) {
	var Segments []int
	for S := range o.Segments {
		Segments = append(Segments, S)
	}
	sort.Ints(Segments)

	s += StatsHeader()

	for _, SegId := range Segments {
		Seg := o.Segments[SegId]

		s += fmt.Sprintf("Segment '%s' statistics:\n", Seg.Name)

		Seg.RLock()
		var Subnets []int
		for S := range Seg.Subnets {
			Subnets = append(Subnets, int(S))
		}
		sort.Ints(Subnets)

		for _, S := range Subnets {
			Net := Seg.Subnets[uint32(S)]

			Net.RLock()
			s += fmt.Sprintf(" Subnet '%s' (%d/%d/%d leases total/active/expired):\n", Net.NetStr, Net.Capacity(), Net.LeasesActive(), Net.LeasesExpired())
			Net.RUnlock()

			for _, r := range strings.Split(Net.Stats.Dump(), "\n") {
				s += fmt.Sprintf("  %s\n", r)
			}
		}
		Seg.RUnlock()
	}

	return
}

func StatsDumpStruct() (Stats *StatsSegmentsStruct) {
	TimeStart := time.Now()
	Stats = &StatsSegmentsStruct{
		Segments: map[string]*StatsSegmentStruct{},
	}

	var Segments []int
	for S := range o.Segments {
		Segments = append(Segments, S)
	}
	sort.Ints(Segments)

	for _, SegId := range Segments {
		Seg := o.Segments[SegId]

		StatsSeg := &StatsSegmentStruct{
			Name:    Seg.Name,
			Subnets: map[string]*StatsSubnetStruct{},
			Stats:   Seg.Stats.DumpMap(),
		}

		Seg.RLock()
		var Subnets []int
		for S := range Seg.Subnets {
			Subnets = append(Subnets, int(S))
		}
		sort.Ints(Subnets)

		for _, S := range Subnets {
			Net := Seg.Subnets[uint32(S)]

			Net.RLock()
			StatsSubnet := &StatsSubnetStruct{
				Subnet:        Net.NetStr,
				Capacity:      Net.Capacity(),
				LeasesActive:  Net.LeasesActive(),
				LeasesExpired: Net.LeasesExpired(),
				Stats:         Net.Stats.DumpMap(),
			}
			Net.RUnlock()

			StatsSeg.Capacity += StatsSubnet.Capacity
			StatsSeg.LeasesActive += StatsSubnet.LeasesActive
			StatsSeg.LeasesExpired += StatsSubnet.LeasesExpired
			StatsSeg.Subnets[Net.NetStr] = StatsSubnet
		}
		Seg.RUnlock()

		Stats.Segments[Seg.Name] = StatsSeg
	}

	Stats.GenerationTime = time.Since(TimeStart).String()
	return
}

func StatsDumpLeases() (s string) {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)

	var Segments []int
	for S := range o.Segments {
		Segments = append(Segments, S)
	}
	sort.Ints(Segments)

	for _, SegId := range Segments {
		Seg := o.Segments[SegId]

		fmt.Fprintf(w, "Segment '%s':\n", Seg.Name)

		Seg.RLock()
		var Subnets []int
		for S := range Seg.Subnets {
			Subnets = append(Subnets, int(S))
		}
		sort.Ints(Subnets)

		for _, S := range Subnets {
			Net := Seg.Subnets[uint32(S)]

			Net.RLock()
			if len(Net.LeasesByIP) == 0 {
				Net.RUnlock()
				continue
			}

			fmt.Fprintf(w, " Subnet '%s' (%d leases):\n", Net.NetStr, len(Net.LeasesByIP))
			for _, Lease := range Net.LeasesByIP {
				fmt.Fprintf(w, "  %s\t%s (%d sec)\n", aux.IPIntToStr(Lease.IP), aux.MACIntToStr(Lease.MAC), Lease.ExpiresIn())
			}
			Net.RUnlock()
		}
		Seg.RUnlock()
	}

	w.Flush()
	return b.String()
}

func StatsHeader() (s string) {
	s += fmt.Sprintf("Version: %s\n\n", AppInfo)
	s += fmt.Sprintf("Process uptime: %s\n", time.Since(ProcessStartTime).String())
	s += fmt.Sprintf("Memory usage: %.2f MB (will commit sepukku at %dMB)\n", float64(MemoryUsage)/1048576, SepukkuMemoryMB)
	s += fmt.Sprintf("Goroutines: %d\n\n", GoroutineCount)
	return
}
