// +build !windows

package main

import (
	"log/syslog"

	log "github.com/Sirupsen/logrus"
	logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
)

// SyslogEnable is a syslog hook to Logrus
func SyslogEnable(SyslogProto string, SyslogHostPort string) (err error) {
	var hook *logrus_syslog.SyslogHook
	if hook, err = logrus_syslog.NewSyslogHook(SyslogProto, SyslogHostPort, syslog.LOG_INFO, ""); err != nil {
		return
	}

	log.AddHook(hook)
	return
}
