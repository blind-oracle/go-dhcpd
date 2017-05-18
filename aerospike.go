package main

import (
	"fmt"
	aux "mt-aux"
	"time"

	log "github.com/Sirupsen/logrus"
	spike "github.com/aerospike/aerospike-client-go"
)

func LeasesDownloadFromAerospike() (err error) {
	var (
		RecordSet  *spike.Recordset
		Segment    *Segment
		Subnet     *Subnet
		Count      int
		Duplicates int
		ok         bool
	)

	TimeStart := time.Now()

	p := as.SpolicyTimeout(o.ASScanTimeout)
	p.Priority = spike.HIGH
	if RecordSet, err = as.Scan(p, o.ASSetLeases); err != nil {
		return
	}

	for s := range RecordSet.Results() {
		if s.Err != nil {
			err = s.Err
			return
		}

		SegmentId := s.Record.Bins["segment_id"].(int)
		NetAddr := uint32(s.Record.Bins["subnet"].(int))
		IP := uint32(s.Record.Bins["ip"].(int))
		MAC := uint64(s.Record.Bins["mac"].(int))
		Expires := time.Unix(int64(s.Record.Bins["expires"].(int)), 0)

		// Skip expired leases
		if time.Now().After(Expires) {
			continue
		}

		if Segment, ok = o.Segments[SegmentId]; !ok {
			log.Warnf("Segment with ID '%d' not found - skipping subnet '%s' loading", SegmentId, aux.IPIntToStr(NetAddr))
			continue
		}

		if Subnet, ok = Segment.Subnets[NetAddr]; !ok {
			log.Warnf("Subnet '%s' not found in Segment '%s' - skipping lease (%s -> %s)",
				aux.IPIntToStr(NetAddr), Segment.Name, aux.IPIntToStr(IP), aux.MACIntToStr(MAC),
			)

			continue
		}

		Lease := &Lease{
			IP:      IP,
			MAC:     MAC,
			Expires: Expires,
		}

		if _, ok = Subnet.LeasesByMAC[MAC]; !ok {
			Subnet.LeasesByMAC[MAC] = Lease
			Subnet.LeasesByIP[IP] = Lease
		} else {
			Duplicates++
			continue
		}

		Count++

		log.Debugf("Lease '%s' -> '%s' (Subnet '%s', Expires in %d sec) loaded into Segment '%s'",
			aux.IPIntToStr(IP), aux.MACIntToStr(MAC), aux.IPIntToStr(NetAddr), Lease.ExpiresIn(), Segment.Name,
		)
	}

	log.Warnf("%d leases loaded in %s (%d duplicates)", Count, time.Since(TimeStart), Duplicates)
	return
}

func LeaseUploadToAerospike(Segment *Segment, Subnet *Subnet, Lease *Lease) (err error) {
	bins := spike.BinMap{
		"segment_id": Segment.Id,
		"subnet":     Subnet.Net,
		"ip":         Lease.IP,
		"mac":        int64(Lease.MAC),
		"expires":    Lease.Expires.Unix(),
	}

	if err = as.Put(
		as.Wpolicy(Lease.ExpiresIn()+5),
		as.Key(
			o.ASSetLeases,
			fmt.Sprintf("%d:%d", Segment.Id, Lease.IP),
		),
		bins,
	); err != nil {
		log.Errorf("Unable to upload lease %s", aux.IPIntToStr(Lease.IP))
	}

	return
}

func LeaseDeleteFromAerospike(Segment *Segment, Lease *Lease) (err error) {
	if _, err = as.Delete(
		as.Key(
			o.ASSetLeases,
			fmt.Sprintf("%d:%d", Segment.Id, Lease.IP),
		),
	); err != nil {
		log.Errorf("Unable to delete lease %s", aux.IPIntToStr(Lease.IP))
	}

	return
}

func SubnetUploadToAerospike(Subnet *Subnet, Segment *Segment) (err error) {
	bins := spike.BinMap{
		"segment_id": Segment.Id,
		"subnet":     Subnet.Net,
	}

	if err = as.Put(
		as.Wpolicy(-1),
		as.Key(
			o.ASSetSubnets,
			fmt.Sprintf("%d:%d", Segment.Id, Subnet.Net),
		),
		bins,
	); err != nil {
		log.Errorf("Unable to upload subnet %s", Subnet.NetStr)
	}

	return
}

func SubnetsDownloadFromAerospike() (err error) {
	var (
		RecordSet *spike.Recordset
		Segment   *Segment
		Count     int
		ok        bool
	)

	TimeStart := time.Now()

	p := as.SpolicyTimeout(o.ASScanTimeout)
	p.Priority = spike.HIGH
	if RecordSet, err = as.Scan(p, o.ASSetSubnets); err != nil {
		return
	}

	for s := range RecordSet.Results() {
		if s.Err != nil {
			return
		}

		SegmentId := s.Record.Bins["segment_id"].(int)
		NetAddr := uint32(s.Record.Bins["subnet"].(int))

		if Segment, ok = o.Segments[SegmentId]; !ok {
			log.Warnf("Segment with ID '%d' not found - skipping subnet '%s' loading", SegmentId, aux.IPIntToStr(NetAddr))
			continue
		}

		if !Segment.AutoMode {
			log.Warnf("Segment '%s' has automode disabled - will not load it", aux.IPIntToStr(NetAddr))
			continue
		}

		if _, ok = Segment.Subnets[NetAddr]; ok {
			log.Warnf("Subnet '%s' already exists in Segment '%s' - skipping", aux.IPIntToStr(NetAddr), Segment.Name)
			continue
		}

		Segment.Subnets[NetAddr] = GenerateAutoSubnet(NetAddr, Segment)
		Count++

		log.Debugf("Subnet '%s' loaded into Segment '%s'", aux.IPIntToStr(NetAddr), Segment.Name)
	}

	log.Warnf("%d automode subnets loaded in %s", Count, time.Since(TimeStart))
	return
}
