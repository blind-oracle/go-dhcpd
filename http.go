package main

import (
	"fmt"
	"net"
	"runtime"

	"encoding/json"

	log "github.com/Sirupsen/logrus"
	fr "github.com/buaazp/fasthttprouter"
	fh "github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/reuseport"
)

var (
	HTTPRouter = fr.New()
)

func HTTPInit() (err error) {
	// Admin API
	HTTPRouter.GET("/stats/:type", HTTPStatsDump)
	HTTPRouter.GET("/leases/dump", HTTPLeasesDump)
	HTTPRouter.GET("/leases/reload", HTTPLeasesReload)
	HTTPRouter.GET("/log/level/:level", HTTPSetLogLevel)
	HTTPRouter.GET("/log/tickers", HTTPToggleTickers)
	HTTPRouter.GET("/selftest", HTTPSelfTest)
	HTTPRouter.GET("/stacktrace", HTTPStackTrace)

	for _, l := range o.HTTPListen {
		go HTTPServe(l, HTTPRouter)
		log.Warnf("HTTP: Listening to %s", l)
	}

	return
}

func HTTPServe(Listen string, router *fr.Router) {
	var (
		Listener net.Listener
		err      error
	)

	if Listener, err = reuseport.Listen("tcp4", Listen); err != nil {
		log.Fatalf("Unable to init HTTP listener: %s", err)
	}

	s := &fh.Server{
		Handler: router.Handler,
		Name:    AppInfo,

		DisableKeepalive: true,
		LogAllErrors:     true,
	}

	if err = s.Serve(Listener); err != nil {
		log.Fatalf("Unable to init HTTP: %s", err)
	}
}

func HTTPStatsDump(ctx *fh.RequestCtx) {
	switch ctx.UserValue("type").(string) {
	case "global":
		ctx.WriteString(StatsDumpGlobal())
	case "segments":
		ctx.WriteString(StatsDumpSegments())
	case "subnets":
		ctx.WriteString(StatsDumpSubnets())
	case "json":
		js, _ := json.MarshalIndent(StatsDumpStruct(), "", "   ")
		ctx.SetContentType("application/json")
		ctx.Write(js)
	default:
		ctx.SetStatusCode(400)
		ctx.WriteString("Unknown stats type")
	}
}

func HTTPLeasesDump(ctx *fh.RequestCtx) {
	ctx.WriteString(StatsDumpLeases())
}

func HTTPLeasesReload(ctx *fh.RequestCtx) {
	if err, Duration := CacheReload(); err != nil {
		ctx.SetStatusCode(500)
		ctx.WriteString("Unable to reload leases: " + err.Error())
	} else {
		ctx.WriteString("Leases successfully reloaded in " + Duration.String())
	}
}

func HTTPSetLogLevel(ctx *fh.RequestCtx) {
	if l, err := log.ParseLevel(ctx.UserValue("level").(string)); err == nil {
		log.SetLevel(l)
		ctx.WriteString("Loglevel: " + log.GetLevel().String())
		return
	} else {
		ctx.SetStatusCode(400)
		ctx.WriteString("Unable to parse log level: " + err.Error())
	}
}

func HTTPToggleTickers(ctx *fh.RequestCtx) {
	o.LogTickers = !o.LogTickers
	ctx.WriteString(fmt.Sprintf("Tickers: %t", o.LogTickers))
}

func HTTPSelfTest(ctx *fh.RequestCtx) {
	var err error

	if err = as.SelfTest(); err != nil {
		goto out
	}

	if _, err = as.Get(as.Rpolicy(), as.Key(o.ASSetLeases, "testbullshit")); err != nil {
		goto out
	}

out:
	if err != nil {
		ctx.SetStatusCode(500)
	} else {
		ctx.SetStatusCode(204)
	}
}

func HTTPStackTrace(ctx *fh.RequestCtx) {
	buf := make([]byte, 1048576)
	n := runtime.Stack(buf, true)
	ctx.Write(buf[:n])
}
