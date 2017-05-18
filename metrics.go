package main

import (
	"fmt"
	"mt-aux/dhcp"
	"mt-aux/metrics"
	"strconv"
	"time"
)

var (
	InfluxDB *metrics.InfluxDB
)

// Send periodic stats metric
func MetricsSendCleanup(Segment *Segment, Subnet *Subnet, Duration time.Duration, ExpiredByMAC, ExpiredByIP int) (err error) {
	if !o.MetricsEnabled {
		return
	}

	Tags := map[string]string{
		"ServerID":    o.ServerID,
		"SegmentId":   strconv.Itoa(Segment.Id),
		"SegmentName": Segment.Name,
		"Subnet":      Subnet.NetStr,
	}

	Fields := map[string]interface{}{
		"Duration":     int(Duration.Nanoseconds() / 1000),
		"ExpiredByMAC": ExpiredByMAC,
		"ExpiredByIP":  ExpiredByIP,
	}

	InfluxDB.SendMetric(&metrics.InfluxDBMetric{
		Measurement: o.MetricsMeasurementCleanup,
		Timestamp:   time.Now(),

		Tags:   Tags,
		Fields: Fields,
	})

	return
}

// Send periodic stats metric
func MetricsSendStats(Segment *Segment, Subnet *Subnet, Duration time.Duration) (err error) {
	if !o.MetricsEnabled {
		return
	}

	Tags := map[string]string{
		"ServerID":    o.ServerID,
		"SegmentId":   strconv.Itoa(Segment.Id),
		"SegmentName": Segment.Name,
		"Subnet":      Subnet.NetStr,
	}

	Fields := map[string]interface{}{
		"Duration":      int(Duration.Nanoseconds() / 1000),
		"LeasesTotal":   Subnet.Capacity(),
		"LeasesActive":  Subnet.LeasesActive(),
		"LeasesExpired": Subnet.LeasesExpired(),
	}

	InfluxDB.SendMetric(&metrics.InfluxDBMetric{
		Measurement: o.MetricsMeasurementStats,
		Timestamp:   time.Now(),

		Tags:   Tags,
		Fields: Fields,
	})

	return
}

// Send periodic stats segments metric
func MetricsSendStatsSegment(Segment *Segment, Duration time.Duration) (err error) {
	if !o.MetricsEnabled {
		return
	}

	Tags := map[string]string{
		"ServerID":    o.ServerID,
		"SegmentId":   strconv.Itoa(Segment.Id),
		"SegmentName": Segment.Name,
	}

	Fields := map[string]interface{}{
		"Duration":      int(Duration.Nanoseconds() / 1000),
		"LeasesTotal":   Segment.LeasesTotal,
		"LeasesActive":  Segment.LeasesActive,
		"LeasesExpired": Segment.LeasesExpired,
	}

	InfluxDB.SendMetric(&metrics.InfluxDBMetric{
		Measurement: o.MetricsMeasurementStatsSegment,
		Timestamp:   time.Now(),

		Tags:   Tags,
		Fields: Fields,
	})

	return
}

// Send metric about a single DHCP request
func MetricsSendDHCPRequest(Ctx *ReqCtx) (err error) {
	if !o.MetricsEnabled {
		return
	}

	Tags := map[string]string{
		"ServerID":     o.ServerID,
		"LocalIP":      Ctx.LocalIPStr,
		"DHCPRequest":  Ctx.DHCPRequest.String(),
		"DHCPResponse": Ctx.DHCPResponse.String(),
	}

	if Ctx.SegmentCopy != nil {
		Tags["SegmentId"] = strconv.Itoa(Ctx.SegmentCopy.Id)
		Tags["SegmentName"] = Ctx.SegmentCopy.Name
	}

	if Ctx.SubnetCopy != nil {
		Tags["Subnet"] = Ctx.SubnetCopy.NetStr
	}

	if Ctx.DropReason != "" {
		Tags["DropReason"] = Ctx.DropReason
	}

	if Ctx.NAKReason != "" {
		Tags["NAKReason"] = Ctx.NAKReason
	}

	if Ctx.LeaseSource != "" {
		Tags["LeaseSource"] = Ctx.LeaseSource
	}

	if Ctx.NotFoundReason != "" {
		Tags["NotFoundReason"] = Ctx.NotFoundReason
	}

	switch Ctx.RelayIPSource {
	case STATS_RELAYIP_GIADDR:
		Tags["RelayIPSource"] = "GIAddr"
	case STATS_RELAYIP_OPTION82:
		Tags["RelayIPSource"] = "Option82"
	case STATS_RELAYIP_UNICAST:
		Tags["RelayIPSource"] = "Unicast"
	}

	Fields := map[string]interface{}{
		"RequestSize": Ctx.RequestSize,
		"MAC":         Ctx.MACStr,
		"RemoteIP":    Ctx.RemoteIPStr,
		"Duration":    int(Ctx.RequestDuration.Nanoseconds() / 1000),
	}

	if Ctx.ResponseSize > 0 {
		Fields["ResponseSize"] = Ctx.ResponseSize
	}

	if Ctx.RelayIP > 0 {
		Fields["RelayIP"] = Ctx.RelayIPStr
	}

	if Ctx.IP > 0 {
		Fields["LeaseIP"] = Ctx.IPStr
	}

	if Ctx.LeaseCopy != nil {
		if Ctx.LeaseCopy.Discover {
			Fields["TxDuration"] = int(Ctx.LeaseCopy.TxDuration().Nanoseconds() / 1000)
		}

		if Ctx.DHCPResponse == dhcp.ACK {
			Fields["TTL"] = int(Ctx.LeaseCopy.ExpiresIn())
		}
	}

	InfluxDB.SendMetric(&metrics.InfluxDBMetric{
		Measurement: o.MetricsMeasurementRequests,
		Timestamp:   time.Now(),

		Tags:   Tags,
		Fields: Fields,
	})

	return
}

func MetricsInit() (err error) {
	InfluxDB = &metrics.InfluxDB{
		InfluxDBHosts: o.MetricsHosts,
		RoundRobin:    true,
	}

	if err = InfluxDB.Init(); err != nil {
		err = fmt.Errorf("Unable to initialize InfluxDB: %s", err)
		return
	}

	return
}
