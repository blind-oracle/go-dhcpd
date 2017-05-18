package main

import (
	"bytes"
	"fmt"
	aux "mt-aux"
	dhcp "mt-aux/dhcp"
	mtspike "mt-aux/spike"
	"strings"
	"text/tabwriter"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"mt-aux/metrics"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/tevino/abool"
)

var (
	MemoryUsage     uint64
	GoroutineCount  int
	SepukkuMemoryMB = 2048
)

var (
	o                *Opts
	as               mtspike.Handle
	Stats            *metrics.Stats
	ProcessStartTime = time.Now()
)

var (
	GitCommit string
	GitBranch string
	BuildDate string
	Version   string
	AppInfo   string
)

var (
	CacheReloading    = abool.New()
	CacheReloadingMtx sync.RWMutex
)

func init() {
	if Version == "" {
		Version = "?"
	}

	AppInfo = fmt.Sprintf("mt-dhcpd (v%s %s %s-%s)", Version, BuildDate, GitCommit, GitBranch)
}

func MySQLConnect() (db *sqlx.DB, err error) {
	db, err = sqlx.Connect("mysql", o.MySQLDSN+"?parseTime=true&loc=Local")
	return
}

func LoadSegments() (err error) {
	for _, s := range o.Segments {
		log.Warnf("Loading subnets for segment '%s'", s.Name)

		TimeStart := time.Now()
		if s.Subnets, s.Masks, err = LoadSubnetsFromSegment(s.Id); err != nil {
			return
		}

		if s.AutoMode {
			s.Masks = append(s.Masks, s.AutoModeMask)
		}

		// Sort masks in reverse order to prefer more specific masks over less specific
		aux.SortUint32Slice(s.Masks)
		s.Masks = aux.ReverseUint32Slice(s.Masks)

		log.Warnf("Segment '%s' loaded in '%s': subnets: %d, distinct masks: %d", s.Name, time.Since(TimeStart), len(s.Subnets), len(s.Masks))
	}

	return nil
}

func LoadSubnetsFromSegment(SegmentId int) (Subnets map[uint32]*Subnet, Masks []uint32, err error) {
	Subnets = make(map[uint32]*Subnet)
	MasksMap := make(map[uint32]bool)

	if len(o.MySQLDSN) == 0 {
		return
	}

	db, err := MySQLConnect()
	if err != nil {
		err = fmt.Errorf("SQL connect error: %s", err)
		return
	}
	defer db.Close()

	var rows1 *sql.Rows
	rows1, err = db.Query(
		"SELECT `subnet_id`, `subnet`, `mask`, `range_start`, `range_end` FROM `dhcp_subnets` WHERE `segment_id` = ? AND `enabled` = 1",
		SegmentId)

	if err != nil {
		err = fmt.Errorf("Query1 error: %s", err)
		return
	}
	defer rows1.Close()

	for rows1.Next() {
		var (
			SubnetID                           int
			NetStr, Mask, RangeStart, RangeEnd string
		)

		if err = rows1.Scan(&SubnetID, &NetStr, &Mask, &RangeStart, &RangeEnd); err != nil {
			err = fmt.Errorf("rows1.Scan() error: %s", err)
			return
		}

		NetInt := aux.IPStrToInt(NetStr)
		Net := &Subnet{
			LeasesByIP:  map[uint32]*Lease{},
			LeasesByMAC: map[uint64]*Lease{},

			Net:        NetInt,
			NetStr:     fmt.Sprintf("%s/%d", NetStr, aux.InetMaskToCIDRBits(aux.IPStrToInt(Mask))),
			Mask:       aux.IPStrToInt(Mask),
			RangeStart: aux.IPStrToInt(RangeStart),
			RangeEnd:   aux.IPStrToInt(RangeEnd),
		}
		Net.StatsInit()

		Net.DHCPOptions = append(Net.DHCPOptions, dhcp.Option{
			Code:  dhcp.OptionSubnetMask,
			Value: net.ParseIP(Mask).To4(),
		})

		// Collect distinct masks
		MasksMap[Net.Mask] = true

		var rows2 *sql.Rows
		// Fetch all options, prefer subnet-specific over common
		rows2, err = db.Query(
			"SELECT `opt`, `value` FROM "+
				"(SELECT `opt`, `value`, `ord` FROM `dhcp_opts_subnet` WHERE `subnet_id` = ? "+
				"UNION "+
				"SELECT `opt`, `value`, `ord` FROM `dhcp_opts_common` WHERE `opt` NOT IN "+
				"(SELECT `opt` FROM `dhcp_opts_subnet` WHERE `subnet_id` = ?)) "+
				"AS `t1` "+
				"ORDER BY `t1`.`opt` ASC, `t1`.`ord` ASC", SubnetID, SubnetID)

		if err != nil {
			err = fmt.Errorf("Query2 error: %s", err)
			return
		}
		defer rows2.Close()

		for rows2.Next() {
			var opt, value string
			if err = rows2.Scan(&opt, &value); err != nil {
				log.Errorf("rows2.Scan() error: %s", err)
				return
			}

			switch opt {
			case "router":
				if Net.Router = aux.IPStrToInt(value); Net.Router == 0 {
					break
				}

				Net.DHCPOptions = append(Net.DHCPOptions, dhcp.Option{
					Code:  dhcp.OptionRouter,
					Value: aux.IPIntToNet(Net.Router).To4(),
				})

			case "dns":
				if DNS := aux.IPStrToInt(value); DNS <= 0 {
					err = fmt.Errorf("Unable to parse DNS '%s' as IP address", value)
					return
				} else {
					Net.DNS = append(Net.DNS, aux.IPIntToNet(DNS))
					Net.DNSStr = append(Net.DNSStr, value)
				}

			case "lease_ttl":
				if Net.LeaseTTL, err = time.ParseDuration(value); err != nil {
					err = fmt.Errorf("Unable to parse 'lease_ttl' '%s' as duration", value)
					return
				}
			}
		}

		var b bytes.Buffer
		w := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
		fmt.Fprintf(w, "Subnet %s loaded:\n", NetStr)
		fmt.Fprintf(w, " Mask:\t%s\n", Mask)
		fmt.Fprintf(w, " Range:\t%s - %s\n", aux.IPIntToStr(Net.RangeStart), aux.IPIntToStr(Net.RangeEnd))
		fmt.Fprintf(w, " Router:\t%s\n", aux.IPIntToStr(Net.Router))
		fmt.Fprintf(w, " DNS:\t%s\n", strings.Join(Net.DNSStr, ", "))
		fmt.Fprintf(w, " Lease TTL:\t%s\n", Net.LeaseTTL)
		w.Flush()

		for _, v := range strings.Split(b.String(), "\n") {
			log.Warnf(v)
		}

		// Sanity checks
		if len(Net.DNS) == 0 {
			log.Warnf("WARNING! No DNS servers defined for network %s", NetStr)
		}

		if Net.LeaseTTL <= 0 {
			log.Warnf("WARNING! Lease TTL not defined for network %s", NetStr)
		}

		if Net.Router <= 0 {
			log.Warnf("WARNING! Router not defined for network %s", NetStr)
		}

		Subnets[NetInt] = Net
	}

	for m, _ := range MasksMap {
		Masks = append(Masks, m)
	}

	return
}

func GenerateAutoSubnet(NetAddr uint32, Segment *Segment) (Net *Subnet) {
	// Construct subnet model
	Net = &Subnet{
		Dynamic: true,

		LeasesByIP:  map[uint32]*Lease{},
		LeasesByMAC: map[uint64]*Lease{},

		Net:    NetAddr,
		NetStr: fmt.Sprintf("%s/%d", aux.IPIntToStr(NetAddr), aux.InetMaskToCIDRBits(Segment.AutoModeMask)),

		Mask:     Segment.AutoModeMask,
		LeaseTTL: Segment.AutoModeLeaseTTL,

		RangeStart: NetAddr + Segment.AutoModeRangeStart,
		RangeEnd:   NetAddr + Segment.AutoModeRangeEnd,
	}
	Net.StatsInit()

	Net.DHCPOptions = append(Net.DHCPOptions,
		dhcp.Option{
			Code:  dhcp.OptionRouter,
			Value: aux.IPIntToNet(NetAddr + Segment.AutoModeRouter).To4(),
		},
	)

	Net.DHCPOptions = append(Net.DHCPOptions,
		dhcp.Option{
			Code:  dhcp.OptionSubnetMask,
			Value: aux.IPIntToNet(Net.Mask).To4(),
		},
	)

	return
}

func CacheReload() (err error, Duration time.Duration) {
	if CacheReloading.SetToIf(false, true) {
		err = fmt.Errorf("Cache reload already in progress")
		log.Errorf("%s", err)
		return
	}

	defer CacheReloading.UnSet()

	TimeStart := time.Now()
	log.Warnf("Starting to reload cache from Aerospike...")

	CacheReloadingMtx.Lock()
	defer CacheReloadingMtx.Unlock()

	for _, Seg := range o.Segments {
		Seg.DeleteDynamicSubnets()
	}

	if err = SubnetsDownloadFromAerospike(); err != nil {
		err = fmt.Errorf("Unable to download subnets from Aerospike: %s", err)
		log.Warnf("%s", err)
		return
	}

	if err = LeasesDownloadFromAerospike(); err != nil {
		err = fmt.Errorf("Unable to download leases from Aerospike: %s", err)
		log.Warnf("%s", err)
		return
	}

	Duration = time.Since(TimeStart)
	log.Warnf("Cache reloaded in %s", Duration)
	return
}

func main() {
	var (
		err error
		wg  sync.WaitGroup
	)

	log.Warnf("Starting %s", AppInfo)

	if o, err = ConfigLoad(); err != nil {
		log.Fatalf("Unable to load config file: %s", err)
	}

	if err = LoadSegments(); err != nil {
		log.Fatalf("Segments loading error: %s", err)
	}

	// Initialize Aerospike
	as = mtspike.Handle{
		Hosts:     o.ASHosts,
		Namespace: o.ASNamespace,
	}

	// Connect to Aerospike
	if err = as.Connect(); err != nil {
		log.Fatalf("Unable to connect to Aerospike: %s", err)
	}
	log.Warnf("Aerospike connected")

	sigchannel := make(chan os.Signal, 1)
	signal.Notify(sigchannel, syscall.SIGHUP)
	signal.Notify(sigchannel, syscall.SIGTERM)
	signal.Notify(sigchannel, syscall.SIGUSR1)
	signal.Notify(sigchannel, os.Interrupt)

	go func() {
		for sig := range sigchannel {
			switch sig {
			case syscall.SIGHUP:
				go CacheReload()
			case syscall.SIGUSR1:
				log.Warnf("Got SIGUSR1, dumping statistics")
			case os.Interrupt, syscall.SIGTERM:
				log.Warnf("Got SIGTERM, shutting down")
				HandleShutdown()
			}
		}
	}()

	if len(o.HTTPListen) > 0 {
		if err = HTTPInit(); err != nil {
			log.Fatalf("Error initializing HTTP: %s", err)
		}
	}

	if len(o.DHCPListen) == 0 {
		log.Fatal("No DHCP listening address defined")
	}

	if err = SubnetsDownloadFromAerospike(); err != nil {
		log.Fatalf("Unable to load subnets from Aerospike: %s", err)
	}

	if err = LeasesDownloadFromAerospike(); err != nil {
		log.Fatalf("Unable to load leases from Aerospike: %s", err)
	}

	DHCPBackend = ConstructBackend()
	DHCPBackend.Init()

	MetricsInit()
	for _, v := range o.DHCPListen {
		wg.Add(1)

		go func(ip string) {
			defer wg.Done()
			DHCPServe(net.ParseIP(ip).To4())
		}(v)
	}

	go MiscMemoryMonitor()
	wg.Wait()
}

func HandleShutdown() {
	os.Exit(0)
}

func MiscMemoryMonitor() {
	var err error

	for {
		if MemoryUsage, GoroutineCount, err = aux.MiscMemoryAndGoroutineMonitor(uint64(SepukkuMemoryMB)*1048576, 50000); err != nil {
			log.Fatal(err)
		}

		time.Sleep(5 * time.Second)
	}
}
