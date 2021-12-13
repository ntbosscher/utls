package tls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
)

type InterceptCallback func(conn net.Conn, input *ClientHelloResult, err error)

type tlsIntercepted struct {
	net.Conn

	mu            sync.RWMutex
	helloFinished bool
	length        int
	hello         bytes.Buffer

	callback InterceptCallback
}

func (t *tlsIntercepted) Read(b []byte) (n int, err error) {

	n, err = t.Conn.Read(b)

	t.mu.RLock()
	if t.helloFinished {
		t.mu.RUnlock()
		return n, err
	}

	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.helloFinished {
		t.length += n

		if t.hello.Len()+n < 2048 {
			t.hello.Write(b[0:n])
		}
	}

	return n, err
}

func (t *tlsIntercepted) Write(b []byte) (n int, err error) {

	t.mu.RLock()
	if t.helloFinished || t.length == 0 {
		t.mu.RUnlock()
		return t.Conn.Write(b)
	}

	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.helloFinished = true

	raw := t.hello.Bytes()

	msg, err := decodeClientHello(raw)
	t.callback(t.Conn, msg, err)

	return t.Conn.Write(b)
}

func decodeClientHello(data []byte) (*ClientHelloResult, error) {
	if len(data) < 4+5 {
		return nil, errors.New("not enough data")
	}

	data = data[5:] // remove header

	if data[0] != typeClientHello {
		return nil, errors.New(fmt.Sprint("unexpected message type: ", data[0]))
	}

	hlo := &ClientHelloResult{}
	if err := hlo.Unmarshal(data); err != nil {
		return nil, err
	}

	return hlo, nil
}

type tlsDebug struct {
	net.Listener
	callback InterceptCallback
}

func (t tlsDebug) Accept() (net.Conn, error) {
	cn, err := t.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &tlsIntercepted{Conn: cn, callback: t.callback}, nil
}

func InterceptHelloWrapper(listen net.Listener, callback InterceptCallback) net.Listener {
	return &tlsDebug{Listener: listen, callback: callback}
}

func GetUConfigFromClientHello(input []byte) (*UConfig, error) {

	msg := &ClientHelloResult{}

	err := json.Unmarshal(input, msg)
	if err != nil {
		return nil, err
	}

	cfg := &UConfig{Config: &Config{}}

	versions := removeGrease(msg.Extensions.FindByTypeOrDefault(&SupportedVersionsExtension{Versions: supportedVersions}).(*SupportedVersionsExtension).Versions)
	cfg.MaxVersion = maxUint16(versions)
	cfg.MinVersion = minUint16(versions)
	cfg.HelloVersion = msg.Vers

	cfg.CipherSuites = msg.CipherSuites

	if msg.SecureRenegotiationSupported {
		cfg.Renegotiation = RenegotiateOnceAsClient
	}

	cfg.NextProtos = msg.Extensions.FindByTypeOrDefault(&ALPNExtension{AlpnProtocols: []string{"http/1.1"}}).(*ALPNExtension).AlpnProtocols
	cfg.Extensions = msg.Extensions

	msg.Extensions.FindByTypeOrDefault(&SNIExtension{}).(*SNIExtension).ServerName = ""
	msg.Extensions.FindByTypeOrDefault(&PaddingExtension{}).(*PaddingExtension).GetPaddingLen = BoringPaddingStyle

	return cfg, nil
}

func maxUint16(input []uint16) uint16 {
	max := input[0]
	for _, item := range input {
		if item > max {
			max = item
		}
	}

	return max
}

func minUint16(input []uint16) uint16 {
	min := input[0]
	for _, item := range input {
		if item < min {
			min = item
		}
	}

	return min
}

func removeGrease(input []uint16) []uint16 {
	var out []uint16

	for _, item := range input {
		if !IsGrease(item) {
			out = append(out, item)
		}
	}

	return out
}
