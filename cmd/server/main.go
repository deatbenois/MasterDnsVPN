package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/udpserver"
)

func main() {
	cfg, err := config.LoadServerConfig("server_config.toml")
	if err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("Server startup failed: %v\n", err))
		os.Exit(1)
	}

	log := logger.New("MasterDnsVPN Go Server", cfg.LogLevel)
	keyInfo, err := security.EnsureServerEncryptionKey(cfg)
	if err != nil {
		log.Errorf("[X] <red>Encryption Key Setup Failed</red>: <yellow>%v</yellow>", err)
		os.Exit(1)
	}

	srv := udpserver.New(cfg, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Infof("[*] <green>Server Configuration Loaded</green>")
	log.Infof(
		"[*] <green>UDP Listener</green>: <cyan>%s</cyan>  |  Readers: <magenta>%d</magenta>  |  Workers: <magenta>%d</magenta>",
		cfg.Address(),
		cfg.UDPReaders,
		cfg.DNSRequestWorkers,
	)
	log.Infof(
		"[*] <green>Encryption Method</green>: <cyan>%s</cyan> <gray>(id=%d)</gray>",
		keyInfo.MethodName,
		keyInfo.MethodID,
	)
	if keyInfo.Generated {
		log.Warnf(
			"[!] <yellow>Encryption Key Generated</yellow> and saved to <cyan>%s</cyan>",
			keyInfo.Path,
		)
	} else {
		log.Infof(
			"[*] <green>Encryption Key Loaded</green> from <cyan>%s</cyan>",
			keyInfo.Path,
		)
	}
	log.Infof("[*] <green>Active Encryption Key</green>: <yellow>%s</yellow>", keyInfo.Key)
	log.Infof("[*] <green>Starting UDP Server</green> on <cyan>%s</cyan>", cfg.Address())

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("[X] <red>Server Stopped Unexpectedly</red>: <yellow>%v</yellow>", err)
		os.Exit(1)
	}

	log.Infof("[*] <yellow>Server Stopped</yellow>")
}
