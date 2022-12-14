package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

var (
	listeners []*http.Server
	handler   *messageHandler
)

type Config struct {
	Provider string
	Address  string
}

func Start(cfg Config) {
	handler = NewMessageHandler(cfg.Provider)
	if err := handler.Start(); err != nil {
		log.Fatalln(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", processReq)

	addrs := extractAddr(cfg.Address)
	for _, a := range addrs {
		s := &http.Server{Addr: a, Handler: mux}
		listeners = append(listeners, s)
		go func(addr string) {
			if err := s.ListenAndServe(); err != nil {
				log.Fatalln(err)
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
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var sessID string
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		sessID = cookie.Value
	}

	var req *Req
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	resp := handler.DispatchCommand(req, sessID, w)

	json, err := json.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

func extractAddr(listen string) []string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		log.Fatal(err)
	}
	if !strings.HasPrefix(host, "<") {
		return []string{fmt.Sprintf("%s:%s", host, port)}
	}

	host = strings.TrimPrefix(host, "<")
	host = strings.TrimSuffix(host, ">")

	ief, err := net.InterfaceByName(host)
	if err != nil {
		log.Fatal(err)
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
		if ip.To4() != nil {
			res = append(res, fmt.Sprintf("%s:%s", ip.String(), port))
		} else {
			res = append(res, fmt.Sprintf("[%s]:%s", ip.String(), port))
		}
	}
	return res
}
