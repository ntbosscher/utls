package tls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	http "github.com/ntbosscher/uhttp"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

func toUConfig(cfg *Config) *UConfig {
	return &UConfig{
		Config: cfg,
	}
}

func testHttpServer() context.CancelFunc {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(wr http.ResponseWriter, rq *http.Request) {
		wr.Write([]byte("hi"))
	})

	server := &http.Server{
		Addr:        ":9001",
		Handler:     mux,
		IdleTimeout: 1 * time.Second,
		TLSConfig:   &tls.Config{
			// MaxVersion: VersionTLS12,
		},
		// disables h2
		// TLSNextProto: make(map[string]func(*http.Server, http.TLSConn, http.Handler)),
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Println(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	callback := func(cn net.Conn, msg *ClientHelloResult, err error) {
		if err != nil {
			log.Println(err)
			return
		}

		// standardize PaddingLen b/c we only care that it's non-zero
		padExt := msg.Extensions.FindByTypeOrDefault(&PaddingExtension{}).(*PaddingExtension)
		if padExt.WillPad {
			padExt.PaddingLen = 1
		}

		keyExt := msg.Extensions.FindByTypeOrDefault(&KeyShareExtension{}).(*KeyShareExtension)
		for i, ks := range keyExt.KeyShares {
			if IsGrease(uint16(ks.Group)) {
				// retain grease data b/c it's consistent
				continue
			}

			// remove KeyShares data b/c it's randomized
			keyExt.KeyShares[i].Data = nil
		}

		// remove SessionId b/c it's random everytime
		msg.SessionId = nil

		bt, err := json.MarshalIndent(msg, "", "\t")
		if err != nil {
			log.Println(err)
		}

		fmt.Println(string(bt))
	}

	go func() {
		for {
			err = server.ServeTLS(InterceptHelloWrapper(ln, callback), "./localhost.crt", "./localhost.key")
			if err != nil {
				log.Println(err)
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
		}
	}()

	return func() {
		cancel()
		server.Close()
		ln.Close()
	}
}

var extBytes = []byte(`{
	"Vers": 771,
	"SessionId": "G+eO00f2x7BDeeoxysuycK1rK38NnvFQis3R88iIyR0=",
	"CipherSuites": [
		43690,
		4865,
		4866,
		4867,
		49195,
		49199,
		49196,
		49200,
		52393,
		52392,
		49171,
		49172,
		156,
		157,
		47,
		53
	],
	"CompressionMethods": "AA==",
	"SecureRenegotiationSupported": false,
	"Extensions": [
		{
			"ID": 2570,
			"Params": {
				"body": "",
				"value": "0x0a0a"
			}
		},
		{
			"ID": 0,
			"Params": {
				"ServerName": "localhost"
			}
		},
		{
			"ID": 23,
			"Params": {}
		},
		{
			"ID": 65281,
			"Params": {
				"Data": "0x00"
			}
		},
		{
			"ID": 10,
			"Params": {
				"curves": "0x0a0a 0x001d 0x0017 0x0018"
			}
		},
		{
			"ID": 11,
			"Params": {
				"supportedPoints": "0x00"
			}
		},
		{
			"ID": 35,
			"Params": {
				"Session": null
			}
		},
		{
			"ID": 16,
			"Params": {
				"AlpnProtocols": [
					"h2",
					"http/1.1"
				]
			}
		},
		{
			"ID": 5,
			"Params": {}
		},
		{
			"ID": 13,
			"Params": {
				"supportedSignatureAlgorithms": "0x0403 0x0804 0x0401 0x0503 0x0805 0x0501 0x0806 0x0601"
			}
		},
		{
			"ID": 18,
			"Params": {}
		},
		{
			"ID": 51,
			"Params": {
				"KeyShares": [
					{
						"Data": "0x00",
						"Group": "0x0a0a"
					},
					{
						"Data": "0x98 0xfe 0x8b 0x03 0x86 0x8b 0xf8 0x8a 0xc0 0x54 0x1b 0x3a 0x67 0x51 0x83 0x63 0x98 0x62 0xa4 0x60 0x98 0x29 0x2b 0xe9 0xd4 0x2b 0xe6 0x79 0x97 0x21 0x73 0x26",
						"Group": "0x001d"
					}
				]
			}
		},
		{
			"ID": 45,
			"Params": {
				"modes": "0x01"
			}
		},
		{
			"ID": 43,
			"Params": {
				"versions": "0x0a0a 0x0304 0x0303 0x0302 0x0301"
			}
		},
		{
			"ID": 27,
			"Params": {
				"Data": "0x02 0x00 0x02",
				"Id": 27
			}
		},
		{
			"ID": 17513,
			"Params": {
				"Data": "0x00 0x03 0x02 0x68 0x32",
				"Id": 17513
			}
		},
		{
			"ID": 2570,
			"Params": {
				"body": "0x00",
				"value": "0x0a0a"
			}
		},
		{
			"ID": 21,
			"Params": {
				"PaddingLen": 202,
				"WillPad": true
			}
		}, {
			"ID": 41,
			"Params": {}
		}
	]
}`)

func TestMockChrome96(t *testing.T) {

	cancel := testHttpServer()
	defer cancel()

	config, err := GetUConfigFromClientHello(extBytes)
	if err != nil {
		t.Fatal(err)
	}

	cache := NewLRUClientSessionCache(10)

	cli := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			GetTLSClient: func(conn net.Conn, cfg *tls.Config) http.TLSConn {
				cn, err := ForUHttp(conn, config, cfg)
				if err != nil {
					log.Println(err)
				}

				cn.config.ClientSessionCache = cache
				return cn
			},
			ForceAttemptHTTP2: config.AttemptHTTP2(),
		},
	}

	if err != nil {
		t.Fatal(err)
	}

	rs, err := cli.Get("https://localhost:9001/")
	if err != nil {
		t.Fatal(err)
	}

	rs.Body.Close()
	cli.CloseIdleConnections()

	rs, err = cli.Get("https://localhost:9001/")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("proto", rs.Proto)

	defer rs.Body.Close()
	dt, _ := ioutil.ReadAll(rs.Body)

	fmt.Println(string(dt))
}

func TestT(t *testing.T) {
	config, err := GetUConfigFromClientHello(extBytes)
	if err != nil {
		t.Fatal(err)
	}

	cache := NewLRUClientSessionCache(10)

	cli := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			GetTLSClient: func(conn net.Conn, cfg *tls.Config) http.TLSConn {
				cn, err := ForUHttp(conn, config, cfg)
				if err != nil {
					log.Println(err)
				}

				cn.config.ClientSessionCache = cache
				return cn
			},
			ForceAttemptHTTP2: config.AttemptHTTP2(),
		},
	}

	if err != nil {
		t.Fatal(err)
	}

	rs, err := cli.Get("https://sd.iperceptions.com/ius-359cd6b861125d638f6cea04ffb14739/17331_637683606272607641")
	if err != nil {
		t.Fatal(err)
	}

	rs.Write(os.Stdout)
	rs.Body.Close()

	rs, err = cli.Get("https://am.contobox.com/v3/frontend/creatives/getcode.js?ph_id=cbox_ph_4241673&zone_id=74065&clientparam=&lid=%7B%22a%22%3A%22rona.ca%22%7D&sourceUrl=&ifr=0&isSF=nosf&clicktag=&fromurl=https%3A%2F%2Fwww.rona.ca%2Fen&nomraid=true&ref=https%3A%2F%2Fwww.google.ca%2F")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println()

	rs.Write(os.Stdout)
	rs.Body.Close()
}

func TestA(t *testing.T) {
	config, err := GetUConfigFromClientHello(extBytes)
	if err != nil {
		t.Fatal(err)
	}

	cache := NewLRUClientSessionCache(10)

	cli := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			GetTLSClient: func(conn net.Conn, cfg *tls.Config) http.TLSConn {
				cn, err := ForUHttp(conn, config, cfg)
				if err != nil {
					log.Println(err)
				}

				cn.config.ClientSessionCache = cache
				return cn
			},
			ForceAttemptHTTP2: config.AttemptHTTP2(),
		},
	}

	if err != nil {
		t.Fatal(err)
	}

	rs, err := cli.Get("https://whatwebcando.today/foreground-detection.html")
	if err != nil {
		t.Fatal(err)
	}

	rs.Write(os.Stdout)
	rs.Body.Close()
}
