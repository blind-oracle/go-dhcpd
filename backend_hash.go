package main

import (
	aux "mt-aux"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
)

type BackendHash struct {
	WorkersMtx sync.RWMutex // Make sure workers do not interfere with each other
}

func (b *BackendHash) Init() (err error) {
	go b.StatsWorker(o.DHCPStatsInterval)
	go b.CleanupWorker(o.DHCPCleanupInterval)
	return
}

func (b *BackendHash) StatsWorker(Interval time.Duration) {
	for {
		time.Sleep(Interval)

		b.WorkersMtx.Lock()
		CacheReloadingMtx.RLock()

		for _, Segment := range o.Segments {
			Segment.LeasesTotal, Segment.LeasesActive, Segment.LeasesExpired = 0, 0, 0
			Segment.RLock()

			TimeStart := time.Now()
			for _, Subnet := range Segment.Subnets {
				TimeStartSubnet := time.Now()
				Segment.LeasesTotal += Subnet.Capacity()

				Subnet.Lock()
				Subnet.UpdateStatsNoLock()
				Segment.LeasesActive += Subnet.LeasesActiveCount
				Segment.LeasesExpired += Subnet.LeasesExpiredCount
				Subnet.Unlock()

				go MetricsSendStats(Segment, Subnet, time.Since(TimeStartSubnet))
			}
			Duration := time.Since(TimeStart)

			go MetricsSendStatsSegment(Segment, Duration)

			if o.LogTickers {
				log.Warnf(
					"Ticker: StatsWorker(): Segment %s (%d) done in %s: %d subnets processed, %d/%d/%d leases total/active/expired",
					Segment.Name, Segment.Id, Duration, len(Segment.Subnets), Segment.LeasesTotal, Segment.LeasesActive, Segment.LeasesExpired,
				)
			}

			Segment.RUnlock()
		}

		CacheReloadingMtx.RUnlock()
		b.WorkersMtx.Unlock()
	}
}

func (b *BackendHash) CleanupWorker(Interval time.Duration) {
	var (
		ExpiredByMAC, ExpiredByIP           int
		ExpiredByMACTotal, ExpiredByIPTotal int
	)

	for {
		time.Sleep(Interval)

		b.WorkersMtx.Lock()
		CacheReloadingMtx.RLock()

		for _, Segment := range o.Segments {
			ExpiredByMACTotal, ExpiredByIPTotal = 0, 0
			Segment.RLock()

			TimeStart := time.Now()
			for _, Subnet := range Segment.Subnets {
				TimeStartSubnet := time.Now()
				ExpiredByMAC, ExpiredByIP = Subnet.CleanupExpired()
				go MetricsSendCleanup(Segment, Subnet, time.Since(TimeStartSubnet), ExpiredByMAC, ExpiredByIP)

				ExpiredByMACTotal += ExpiredByMAC
				ExpiredByIPTotal += ExpiredByIP
			}
			Duration := time.Since(TimeStart)

			if o.LogTickers {
				log.Warnf(
					"Ticker: CleanupWorker(): Segment %s (%d): done in %s: %d subnets processed, expired: %d by MAC, %d by IP",
					Segment.Name, Segment.Id, Duration, len(Segment.Subnets), ExpiredByMACTotal, ExpiredByIPTotal,
				)
			}

			Segment.RUnlock()
		}

		CacheReloadingMtx.RUnlock()
		b.WorkersMtx.Unlock()
	}
}

func (b *BackendHash) LeaseFind(Ctx *ReqCtx) (err error) {
	var (
		Lease *Lease
		ip    uint32
		ok    bool
	)

	// Lock whole subnet during processing
	Ctx.Subnet.Lock()

	// Check if client's MAC already has a lease in this subnet
	if Lease, ok = Ctx.Subnet.LeasesByMAC[Ctx.MAC]; ok {
		if Lease.MAC != Ctx.MAC {
			Ctx.LogWarnf("Found lease '%s', but it points to lease with another MAC '%s', cleaning it", aux.IPIntToStr(Lease.IP), aux.MACIntToStr(Lease.MAC))
			delete(Ctx.Subnet.LeasesByMAC, Ctx.MAC)
			goto search
		}

		if Lease, ok = Ctx.Subnet.LeasesByIP[Lease.IP]; !ok {
			Ctx.LogDebugf("Found lease, but corresponding lease in LeasesByIP not found, cleaning it")
			delete(Ctx.Subnet.LeasesByMAC, Ctx.MAC)
			goto search
		}

		if Lease.MAC != Ctx.MAC {
			Ctx.LogDebugf("Found lease '%s', but it points to lease with another MAC '%s'", aux.IPIntToStr(Lease.IP), aux.MACIntToStr(Lease.MAC))
			goto search
		}

		Ctx.SetRequestedIP(Lease.IP)
		Ctx.LogDebugf("Found existing lease: %s (expired=%t)", Ctx.IPStr, Lease.Expired())
		Lease.Expires = Ctx.RequestStart.Add(o.DHCPGraceTTL)
		Lease.DiscoverSet()
		Ctx.StatsInc(STATS_LEASE_EXISTING)
		Ctx.LeaseSource = LEASE_SRC_EXISTING
		goto out
	}

search:
	Ctx.LogDebugf("Existing lease not found, trying to reserve")

	// Try some random IPs first
	for i := 0; i < o.DHCPRandomTries; i++ {
		ip = aux.RandRangeUint32(Ctx.Subnet.RangeStart, Ctx.Subnet.RangeEnd)

		if b.LeaseAdd(Ctx, ip) {
			Ctx.SetRequestedIP(ip)
			Ctx.LogDebugf("Found random lease: %s", Ctx.IPStr)
			Ctx.StatsInc(STATS_LEASE_RANDOM)
			Ctx.LeaseSource = LEASE_SRC_RANDOM
			goto out
		}
	}

	// Iterate through subnet range to find free lease
	for ip = Ctx.Subnet.RangeStart; ip <= Ctx.Subnet.RangeEnd; ip++ {
		if b.LeaseAdd(Ctx, ip) {
			Ctx.SetRequestedIP(ip)
			Ctx.LogDebugf("Found range lease: %s", Ctx.IPStr)
			Ctx.StatsInc(STATS_LEASE_RANGE)
			Ctx.LeaseSource = LEASE_SRC_RANGE
			break
		}
	}

out:
	Ctx.Subnet.Unlock()

	if Ctx.IP <= 0 {
		Ctx.StatsInc(STATS_LEASE_NO_FREE)
	}

	return
}

// Try to add lease (it assumes an already locked subnet)
func (b *BackendHash) LeaseAdd(Ctx *ReqCtx, ip uint32) bool {
	var (
		L  *Lease
		ok bool
	)

	if L, ok = Ctx.Subnet.LeasesByIP[ip]; ok {
		// Lease already occupied, check if it's expired
		if !L.Expired() {
			return false
		}

		Ctx.LogDebugf("Lease '%s' is occupied, but already expired - taking over", aux.IPIntToStr(ip))
	}

	L = &Lease{
		IP:      ip,
		MAC:     Ctx.MAC,
		Expires: Ctx.RequestStart.Add(o.DHCPGraceTTL),
	}
	L.DiscoverSet()

	Ctx.Subnet.LeasesByIP[ip] = L
	Ctx.Subnet.LeasesByMAC[Ctx.MAC] = L
	return true
}

// Tries to get & update lease
func (b *BackendHash) LeaseCheckAndUpdate(Ctx *ReqCtx) (err error) {
	var (
		ok    bool
		valid bool
	)

	Ctx.Subnet.Lock()
	if Ctx.Lease, ok = Ctx.Subnet.LeasesByIP[Ctx.IP]; !ok {
		Ctx.LogDebugf("Lease for IP '%s' not found", Ctx.IPStr)
		Ctx.NotFoundReason = NOTFOUND_NOTFOUND
		goto out
	}

	if Ctx.Lease.Expired() {
		Ctx.LogDebugf("Lease for IP '%s' found, but it already expired", Ctx.IPStr)
		Ctx.NotFoundReason = NOTFOUND_EXPIRED
		goto out
	}

	if Ctx.Lease.MAC != Ctx.MAC {
		Ctx.LogDebugf("Lease for IP '%s' found, but belongs to another MAC: '%s", Ctx.IPStr, aux.MACIntToStr(Ctx.Lease.MAC))
		Ctx.NotFoundReason = NOTFOUND_ANOTHER_MAC
		goto out
	}

	Ctx.Lease.Expires = Ctx.RequestStart.Add(Ctx.Subnet.LeaseTTL)
	Ctx.LogDebugf("Lease for IP '%s' updated to expire @ %s", Ctx.IPStr, aux.TimeString(Ctx.Lease.Expires))
	valid = true

out:
	if valid {
		Ctx.LeaseCopy = &Lease{}
		*Ctx.LeaseCopy = *Ctx.Lease
		Ctx.Lease.Discover = false
		go LeaseUploadToAerospike(Ctx.SegmentCopy, Ctx.SubnetCopy, Ctx.LeaseCopy)
	} else {
		Ctx.Lease = nil
	}

	Ctx.Subnet.Unlock()
	return
}

// Deletes the lease if it belongs to context MAC
// Doesn't care if it expired or not
func (b *BackendHash) LeaseCheckAndDelete(Ctx *ReqCtx) (err error) {
	var (
		Lease *Lease
		ok    bool
	)

	Ctx.Subnet.Lock()
	if Lease, ok = Ctx.Subnet.LeasesByIP[Ctx.IP]; ok {
		if Lease.MAC != Ctx.MAC {
			Ctx.LogDebugf("Lease for IP '%s' found, but it belongs to another MAC: %s", Ctx.IP, aux.MACIntToStr(Lease.MAC))
			goto out
		}

		delete(Ctx.Subnet.LeasesByIP, Ctx.IP)
		delete(Ctx.Subnet.LeasesByMAC, Ctx.MAC)
		go LeaseDeleteFromAerospike(Ctx.Segment, Lease)

		Ctx.LogDebugf("Lease for IP '%s' removed", Ctx.IP)
		goto out
	}

	Ctx.LogDebugf("Lease for IP '%s' not found", Ctx.IP)

out:
	Ctx.Subnet.Unlock()
	return
}
