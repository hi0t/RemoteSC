package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"remotesc/server"
)

const DefaultPort = "44555"

func main() {
	log.SetFlags(0)

	var cfg server.Config

	cfg.Provider = os.Getenv("REMOTESC_PROVIDER")
	if cfg.Provider == "" {
		log.Fatal("Provider not set")
	}

	cfg.Address = os.Getenv("REMOTESC_LISTEN")
	if cfg.Address == "" {
		cfg.Address = fmt.Sprintf(":%s", DefaultPort)
	}

	cfg.Secret = os.Getenv("REMOTESC_SECRET")
	if cfg.Secret == "" {
		log.Fatal("Shared secret not set")
	}

	cfg.Cert = os.Getenv("REMOTESC_CERT")
	if cfg.Cert == "" {
		log.Fatal("TLS certificate not set")
	}

	cfg.Priv = os.Getenv("REMOTESC_PRIV")
	if cfg.Priv == "" {
		log.Fatal("Private key not set")
	}

	server.Start(cfg)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	server.Stop()
}
