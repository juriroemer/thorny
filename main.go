package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

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
	// Use sensor IP in filename when available and include timestamp
	ts := time.Now().Format("2006-01-02T150405")
	// allow configuration of the logging directory via config.Logging.LogDir
	logDir := config.Logging.LogDir
	if logDir == "" {
		logDir = "."
	}
	_ = os.MkdirAll(logDir, 0777)
	logPath := fmt.Sprintf("%s/log-%s.jsonl", logDir, ts)
	if config.Network.PrimaryIP != nil {
		logPath = fmt.Sprintf("%s/log-%s-%s.jsonl", logDir, config.Network.PrimaryIP.String(), ts)
	}
	logFile, _ := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	jsonHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.LevelKey, slog.MessageKey, slog.TimeKey: // drop Level, MSG and slog timestamp
				return slog.Attr{}
			}
			return a
		},
	})
	// Determine sensor IP to include in all logs
	sensorIP := "unknown"
	if config.Network.PrimaryIP != nil {
		sensorIP = config.Network.PrimaryIP.String()
	}
	sensorLogger := slog.New(jsonHandler).With("sensor_ip", sensorIP)

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
			slog.Int("sensor_port", port),
		)
		hr.Activate(port, h, listener, portLogger)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var wg = &sync.WaitGroup{}
	hr.ServeAll(ctx, wg)

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan // Blocks here until interrupted

	// Handle shutdown
	fmt.Println("*********************************\nShutdown signal received\n*********************************")
	cancel()  // Signal cancellation to context.Context
	wg.Wait() // Block here until are workers are done

	fmt.Println("All handlers done, shutting down!")
}
