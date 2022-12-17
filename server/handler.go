package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"time"
)

const (
	sessionCookie  = "Session"
	sessionTimeout = 1 * time.Minute
)

type Req struct {
	Method string          `json:"method"`
	Args   json.RawMessage `json:"args"`
}

type Resp struct {
	Ret            any    `json:"ret,omitempty"`
	Err            uint   `json:"err,omitempty"`
	ErrDescription string `json:"errDescription,omitempty"`
}

type messageHandler struct {
	provider    string
	currSession string
	sessKeeper  *time.Timer
	mu          sync.Mutex
	p11         *pkcs11_ctx
	stopping    bool
}

func NewMessageHandler(provider string) *messageHandler {
	return &messageHandler{
		provider: provider,
	}
}

func (h *messageHandler) Start() (err error) {
	h.p11, err = OpenPKCS11(h.provider)
	return
}

func (h *messageHandler) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.stopping = true
	if h.sessKeeper != nil {
		h.sessKeeper.Stop()
	}
	if h.currSession != "" {
		h.p11.Finalize()
	}
}

func (h *messageHandler) DispatchCommand(r *Req, sessID string, w http.ResponseWriter) *Resp {
	// Usually smart cards do not allow concurrent requests
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.stopping {
		panic("stopping state")
	}

	switch r.Method {
	case "Initialize":
		if h.currSession != "" {
			return &Resp{Err: CKR_CRYPTOKI_ALREADY_INITIALIZED}
		}
		h.currSession = genSessionID()
		cookie := &http.Cookie{Name: sessionCookie, Value: h.currSession}
		http.SetCookie(w, cookie)
		h.sessKeeper = time.AfterFunc(sessionTimeout, h.closeSession)
	case "Finalize":
		h.sessKeeper.Stop()
		h.currSession = ""
	default:
		if h.currSession != sessID {
			return &Resp{Err: CKR_CRYPTOKI_NOT_INITIALIZED}
		}
		h.sessKeeper.Reset(sessionTimeout)
	}

	return h.callMethod(r.Method, r.Args)
}

func (h *messageHandler) closeSession() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sessKeeper.Stop()

	if h.currSession != "" {
		h.p11.Finalize()
	}
	h.currSession = ""
}

func (h *messageHandler) callMethod(method string, args json.RawMessage) *Resp {
	rcvr := reflect.ValueOf(h.p11)
	m := rcvr.MethodByName(method)
	if !m.IsValid() {
		return &Resp{Err: CKR_FUNCTION_FAILED, ErrDescription: fmt.Sprintf("method %s not found", method)}
	}
	mt := m.Type()

	var argv []reflect.Value
	var refs []any
	for i := 0; i < mt.NumIn(); i++ {
		a := reflect.New(mt.In(i))
		argv = append(argv, a.Elem())
		refs = append(refs, a.Interface())
	}

	if refs != nil {
		if err := json.Unmarshal(args, &refs); err != nil {
			return &Resp{Err: CKR_FUNCTION_FAILED, ErrDescription: fmt.Sprintf("%s (%s)", err, method)}
		}
	}

	resp := m.Call(argv)

	var err error
	var ret any
	switch len(resp) {
	case 1:
		if !resp[0].IsNil() {
			err = resp[0].Interface().(error)
		}
	case 2:
		ret = resp[0].Interface()
		if !resp[1].IsNil() {
			err = resp[1].Interface().(error)
		}
	default:
		return &Resp{Err: CKR_FUNCTION_FAILED, ErrDescription: fmt.Sprintf("invalide signature of %s", method)}
	}

	if err == nil {
		return &Resp{Ret: ret, Err: CKR_OK}
	}
	if perr, ok := err.(*pkcs11_err); ok {
		return &Resp{Ret: ret, Err: uint(*perr), ErrDescription: perr.Error()}
	}
	return &Resp{Err: CKR_FUNCTION_FAILED, ErrDescription: err.Error()}
}

func genSessionID() string {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
