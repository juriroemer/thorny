package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/juriroemer/thorny/config"
	"github.com/juriroemer/thorny/filter"
	"github.com/juriroemer/thorny/handler"
	"github.com/juriroemer/thorny/lib"
)

func main() {
	configFile := flag.String("config", "config.yaml", "the path of the config file")
	flag.Parse()

	config, err := config.NewConfig(configFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	// LOGGING
	// TODO add IP to filename, e.g. log-{IP}.jsonl
	logFile, _ := os.OpenFile("log.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	jsonHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.LevelKey, slog.MessageKey, slog.TimeKey: // drop Level, MSG and slog timestamp
				return slog.Attr{}
			}
			return a
		},
	})
	sensorLogger := slog.New(jsonHandler).With("sensor_ip", "ip") // TODO add ip

	// TODO create certs for ssh and tls, add to context
	os.MkdirAll("cert", os.ModePerm)
	tlsUserConf, err := lib.NewTlsUserConfig(config.Tls, config.Network.Ips)
	if err := lib.GenerateSelfSignedCert(tlsUserConf); err != nil {

	}

	/* go func() {
		// TODO use context for things like config
		err := log_snort(config.Snort.Rules)
		if err != nil {
			slog.Warn(err.Error())
		}
	}() */

	fr := filter.NewFilterRegistry()
	fr.Init()

	for _, f := range config.Filters {
		fr.Activate(f)
	}

	// Register, activate and serve configured protocol handlers
	hr := handler.NewHandlerRegistry()
	hr.Init()

	for port, h := range config.Handlers {
		listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", port)) // TODO add error checking
		portLogger := sensorLogger.With(
			slog.Int("port", port),
		)
		hr.Activate(h, listener, portLogger)
	}

	go hr.ServeAll()

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
}
