package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"remotesc/cmd"
	"remotesc/server"

	"github.com/kardianos/service"
)

const DefaultPort = "44555"

type program struct{}

func (p *program) Start(s service.Service) error {
	var cfg server.Config

	cfg.Provider = os.Getenv("REMOTESC_PROVIDER")
	if cfg.Provider == "" {
		return errors.New("provider not configured")
	}
	cfg.Address = os.Getenv("REMOTESC_LISTEN")
	if cfg.Address == "" {
		cfg.Address = fmt.Sprintf(":%s", DefaultPort)
	}
	cfg.Secret = os.Getenv("REMOTESC_SECRET")
	if cfg.Secret == "" {
		return errors.New("shared secret not configured")
	}
	cfg.Cert = os.Getenv("REMOTESC_CERT")
	if cfg.Cert == "" {
		return errors.New("TLS certificate not configured")
	}
	cfg.Priv = os.Getenv("REMOTESC_PRIV")
	if cfg.Priv == "" {
		return errors.New("private key not configured")
	}

	server.Start(cfg)
	return nil
}

func (p *program) Stop(s service.Service) error {
	server.Stop()
	return nil
}

func main() {
	installCmd := flag.NewFlagSet("install", flag.ExitOnError)
	listen := installCmd.String("listen", fmt.Sprintf(":%s", DefaultPort), "Sets the address and port on which the server will accept requests")
	provider := installCmd.String("provider", "", "Path to the pkcs11 module")

	log.SetFlags(0)
	svcConfig := &service.Config{
		Name:        "RemoteSC",
		DisplayName: "RemoteSC",
		Description: "PKCS#11 remote access",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			installCmd.Parse(os.Args[2:])
			if *provider == "" {
				usage()
			}
			testProvider(*provider)

			svcConfig.EnvVars = make(map[string]string)
			svcConfig.EnvVars["REMOTESC_PROVIDER"] = *provider
			svcConfig.EnvVars["REMOTESC_LISTEN"] = *listen
			clientCfg := cmd.Configure(svcConfig.EnvVars)

			if err = s.Install(); err != nil {
				log.Fatal(err)
			}
			fmt.Println(clientCfg)
		case "uninstall":
			if err = s.Uninstall(); err != nil {
				log.Fatal(err)
			}
		default:
			fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", os.Args[1])
			usage()
		}
		os.Exit(0)
	}

	logs, err := s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(&serviceLogger{logs: logs})

	if err = s.Run(); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s install --provider <module> [--listen <address>] \n", os.Args[0])
	fmt.Fprint(os.Stderr, "   or: uninstall\n")
	os.Exit(1)
}

func testProvider(module string) {
	ctx, err := server.OpenPKCS11(module)
	if err != nil {
		log.Fatal(err)
	}
	ctx.Close()
}

type serviceLogger struct {
	logs service.Logger
}

func (s *serviceLogger) Write(p []byte) (n int, err error) {
	s.logs.Error(string(p))
	return len(p), nil
}
