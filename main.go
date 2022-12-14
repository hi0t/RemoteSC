package main

import (
	"fmt"
	"os"
	"os/signal"
	"remotesc/server"
)

const DefaultPort = "44555"

func main() {
	p := os.Getenv("REMOTESC_PROVIDER")
	if p == "" {
		panic("empty provider")
	}

	addr := os.Getenv("REMOTESC_LISTEN")
	if addr == "" {
		addr = fmt.Sprintf(":%s", DefaultPort)
	}

	server.Start(server.Config{Provider: p, Address: addr})

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	server.Stop()
}
