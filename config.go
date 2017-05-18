package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	aux "mt-aux"
	"net"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Knetic/govaluate"
	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	ConfigFilename     string
	goValuateFunctions map[string]govaluate.ExpressionFunction
)

type Opts struct {
	ServerID string
	Segments map[int]*Segment

	MySQLDSN   string
	HTTPListen []string

	MetricsEnabled                 bool
	MetricsHosts                   []string
	MetricsMeasurementRequests     string
	MetricsMeasurementStats        string
	MetricsMeasurementStatsSegment string
	MetricsMeasurementCleanup      string

	DHCPListen          []string
	DHCPGraceTTL        time.Duration
	DHCPRandomTries     int
	DHCPBufferSize      int
	DHCPCleanupInterval time.Duration
	DHCPCleanupAge      time.Duration
	DHCPStatsInterval   time.Duration

	ASNamespace   string
	ASHosts       []string
	ASSetLeases   string
	ASSetSubnets  string
	ASScanTimeout time.Duration

	Syslog      string
	LogLevel    string
	LogrusLevel log.Level
	LogTickers  bool
}

func init() {
	flag.StringVar(&ConfigFilename, "config", "mt-dhcpd", "Config filename (without extension)")

	goValuateFunctions = map[string]govaluate.ExpressionFunction{
		"InRange": func(args ...interface{}) (interface{}, error) {
			return (int64(args[0].(float64)) >= int64(args[1].(float64))) && (int64(args[0].(float64)) <= int64(args[2].(float64))), nil
		},

		"InNetwork": func(args ...interface{}) (interface{}, error) {
			return int64(args[0].(float64))&int64(args[2].(float64)) == int64(args[1].(float64)), nil
		},
	}
}

func ConfigLoad() (o *Opts, err error) {
	flag.Parse()

	viper.SetConfigName(ConfigFilename)
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc")
	viper.AddConfigPath("/usr/local/etc")

	if err = viper.ReadInConfig(); err != nil {
		return
	}

	viper.SetDefault("dhcp.buffer_size", 4*1024*1024)
	viper.SetDefault("dhcp.cleanup_interval", 5*time.Second)
	viper.SetDefault("dhcp.cleanup_age", 60*time.Minute)
	viper.SetDefault("dhcp.stats_interval", 1*time.Second)
	viper.SetDefault("aerospike.scan_timeout", 30*time.Second)

	o = &Opts{
		ServerID: viper.GetString("server_id"),

		MySQLDSN:   viper.GetString("mysql.dsn"),
		HTTPListen: viper.GetStringSlice("http.listen"),

		MetricsEnabled:                 viper.GetBool("metrics.enable"),
		MetricsHosts:                   viper.GetStringSlice("metrics.hosts"),
		MetricsMeasurementRequests:     viper.GetString("metrics.measurement_requests"),
		MetricsMeasurementStats:        viper.GetString("metrics.measurement_stats"),
		MetricsMeasurementStatsSegment: viper.GetString("metrics.measurement_stats_segment"),
		MetricsMeasurementCleanup:      viper.GetString("metrics.measurement_cleanup"),

		DHCPListen:          viper.GetStringSlice("dhcp.listen"),
		DHCPGraceTTL:        viper.GetDuration("dhcp.grace_ttl"),
		DHCPRandomTries:     viper.GetInt("dhcp.random_tries"),
		DHCPBufferSize:      viper.GetInt("dhcp.buffer_size"),
		DHCPCleanupInterval: viper.GetDuration("dhcp.cleanup_interval"),
		DHCPCleanupAge:      viper.GetDuration("dhcp.cleanup_age"),
		DHCPStatsInterval:   viper.GetDuration("dhcp.stats_interval"),

		ASHosts:       viper.GetStringSlice("aerospike.hosts"),
		ASNamespace:   viper.GetString("aerospike.namespace"),
		ASSetLeases:   viper.GetString("aerospike.set_leases"),
		ASSetSubnets:  viper.GetString("aerospike.set_subnets"),
		ASScanTimeout: viper.GetDuration("aerospike.scan_timeout"),

		LogTickers: viper.GetBool("log.tickers"),
	}

	if o.ServerID == "" {
		err = fmt.Errorf("You need to define server_id")
		return
	}

	if o.DHCPGraceTTL <= 0 {
		err = fmt.Errorf("dhcp.grace_ttl should be > 0")
		return
	}

	if o.DHCPBufferSize <= 0 {
		err = fmt.Errorf("dhcp.buffer_size should be > 0")
		return
	}

	if o.ASSetLeases == "" {
		err = fmt.Errorf("aerospike.set_leases should be defined")
		return
	}

	if o.ASSetSubnets == "" {
		err = fmt.Errorf("aerospike.set_subnets should be defined")
		return
	}

	// Logging
	if o.LogLevel = viper.GetString("log.level"); o.LogLevel == "" {
		o.LogLevel = "WARN"
	}

	if o.LogrusLevel, err = log.ParseLevel(o.LogLevel); err != nil {
		err = fmt.Errorf("Unable to parse '%s' as Logrus log level", o.LogLevel)
		return
	}

	log.SetLevel(o.LogrusLevel)
	log.Warnf("Log level: %s", o.LogrusLevel)

	if o.Syslog = viper.GetString("log.syslog"); o.Syslog == "local" {
		SyslogEnable("", "")
	} else if o.Syslog != "" {
		if t := strings.Split(o.Syslog, "/"); len(t) != 2 || (t[1] != "udp" && t[1] != "tcp") {
			err = fmt.Errorf("log.syslog can be either 'local' or 'host:port/protocol'")
			return
		} else {
			if err = SyslogEnable(t[1], t[0]); err != nil {
				err = fmt.Errorf("Unable to enable syslog: %s", err)
				return
			}
		}
	}

	// Load segments
	o.Segments = make(map[int]*Segment)

	Segments := viper.GetStringMap("segments")
	// Iterate through sections, search for segments
	for s := range Segments {
		log.Warnf("Loading segment '%s' ...", s)
		SegCfg := viper.Sub("segments." + s)

		Seg := &Segment{
			Id:         SegCfg.GetInt("id"),
			Name:       s,
			DetectRule: aux.ConvertStringIPandMACToInt(SegCfg.GetString("detect_rule")),
		}
		Seg.StatsInit()

		if Seg.Id <= 0 {
			err = fmt.Errorf("segment.id should be > 0")
			return
		}

		if Seg.DetectExpression, err = govaluate.NewEvaluableExpressionWithFunctions(Seg.DetectRule, goValuateFunctions); err != nil {
			return
		}

		Seg.DNSRandom = SegCfg.GetBool("dns_random")

		SegCfgAM := SegCfg.Sub("automode")
		if SegCfgAM == nil {
			goto result
		}

		Seg.AutoMode = SegCfgAM.GetBool("enable")
		if Seg.AutoModeMask = aux.IPStrToInt(SegCfgAM.GetString("mask")); Seg.AutoModeMask == 0 {
			err = errors.New("Wrong mask")
			return
		}

		if Seg.AutoModeRangeStart = aux.IPStrToInt(SegCfgAM.GetString("range_start")); Seg.AutoModeRangeStart == 0 {
			err = errors.New("Wrong range_start")
			return
		}

		if Seg.AutoModeRangeEnd = aux.IPStrToInt(SegCfgAM.GetString("range_end")); Seg.AutoModeRangeEnd == 0 {
			err = errors.New("Wrong range_end")
			return
		}

		if Seg.AutoModeRouter = aux.IPStrToInt(SegCfgAM.GetString("router")); Seg.AutoModeRouter == 0 {
			err = errors.New("Wrong router")
			return
		}

		if Seg.AutoModeLeaseTTL = SegCfgAM.GetDuration("lease_ttl"); Seg.AutoModeLeaseTTL == 0 {
			err = errors.New("You must specify lease_ttl > 0")
			return
		}

		for _, v := range SegCfgAM.GetStringSlice("dns") {
			if ip := net.ParseIP(v); ip != nil {
				Seg.AutoModeDNS = append(Seg.AutoModeDNS, ip)
			} else {
				err = fmt.Errorf("DNS: Unable to parse as IP address: %s", v)
				return
			}
		}

		if len(Seg.AutoModeDNS) == 0 {
			err = errors.New("You must specify at lease one DNS server")
			return
		}

	result:
		o.Segments[Seg.Id] = Seg

		var b bytes.Buffer
		w := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
		fmt.Fprintf(w, "Segment '%s' (id %d):\n", Seg.Name, Seg.Id)
		fmt.Fprintf(w, " Detect Rule:\t%s\n", SegCfg.GetString("detect_rule"))
		fmt.Fprintf(w, " Detect Rule (converted):\t%s\n", Seg.DetectRule)
		fmt.Fprintf(w, " DNS Random:\t%t\n", Seg.DNSRandom)
		fmt.Fprintf(w, " Automode:\t%t\n", Seg.AutoMode)

		if Seg.AutoMode {
			fmt.Fprintf(w, "  Mask:\t%s\n", aux.IPIntToStr(Seg.AutoModeMask))
			fmt.Fprintf(w, "  Range:\t%s - %s (%d hosts)\n", aux.IPIntToStr(Seg.AutoModeRangeStart), aux.IPIntToStr(Seg.AutoModeRangeEnd), Seg.AutoModeRangeEnd-Seg.AutoModeRangeStart+1)
			fmt.Fprintf(w, "  Router:\t%s\n", aux.IPIntToStr(Seg.AutoModeRouter))
			fmt.Fprintf(w, "  Lease TTL:\t%s\n", Seg.AutoModeLeaseTTL)
			fmt.Fprintf(w, "  DNS:\t%s\n", strings.Join(SegCfgAM.GetStringSlice("dns"), ", "))
		}
		w.Flush()

		for _, v := range strings.Split(b.String(), "\n") {
			log.Warnf(v)
		}
	}

	if len(o.Segments) == 0 {
		err = errors.New("You should specify at least one segment")
		return
	}

	return
}
