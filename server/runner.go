package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
)

const DefaultPort = "25519"

var (
	listeners    []*http.Server
	handler      *messageHandler
	sharedSecret string
)

type Config struct {
	Provider string
	Address  string
	Secret   string
	Cert     string
	Priv     string
}

func Start(cfg Config) {
	handler = NewMessageHandler(cfg.Provider)
	if err := handler.Start(); err != nil {
		log.Fatalf("Failed to start message handler: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", processReq)

	addrs := formatAddr(cfg.Address)
	sharedSecret = cfg.Secret
	cert := decodeCertificate(cfg.Cert, cfg.Priv)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	for _, a := range addrs {
		s := &http.Server{Addr: a, Handler: mux, TLSConfig: tlsConfig}
		listeners = append(listeners, s)
		go func(addr string) {
			if err := s.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}(a)
	}
}

func Stop() {
	for _, l := range listeners {
		l.Shutdown(context.Background())
	}
	handler.Stop()
}

func processReq(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	reqToken := strings.TrimPrefix(authHeader, "Bearer")
	reqToken = strings.TrimSpace(reqToken)
	if reqToken != sharedSecret {
		http.Error(w, "access denited", http.StatusForbidden)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var sessID string
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		sessID = cookie.Value
	}

	var req *Req
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := handler.DispatchCommand(req, sessID, w)

	json, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

func formatAddr(listen string) []string {
	host, port := splitHostPort(listen)
	if host == "" {
		log.Fatalf("Failed to parse listen address: %s", listen)
	}
	if port == "" {
		port = DefaultPort
	}

	if !strings.HasPrefix(host, "<") {
		return []string{net.JoinHostPort(host, port)}
	}

	host = strings.TrimPrefix(host, "<")
	host = strings.TrimSuffix(host, ">")

	ief, err := net.InterfaceByName(host)
	if err != nil {
		log.Fatalf("Failed to find interface: %v", err)
	}
	addrs, err := ief.Addrs()
	if err != nil {
		log.Fatal(err)
	}
	var res []string
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			log.Fatal(err)
		}
		res = append(res, net.JoinHostPort(ip.String(), port))
	}
	return res
}

func splitHostPort(hostPort string) (host, port string) {
	host = hostPort

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 {
		host, port = host[:colon], host[colon+1:]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

func decodeCertificate(encCert, encPriv string) tls.Certificate {
	rawCert, err := base64.StdEncoding.DecodeString(encCert)
	if err != nil {
		log.Fatalf("Unable to decode certificate: %v", err)
	}
	rawPriv, err := base64.StdEncoding.DecodeString(encPriv)
	if err != nil {
		log.Fatalf("Unable to decode private key: %v", err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(rawPriv)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{rawCert},
		PrivateKey:  priv,
	}
}
