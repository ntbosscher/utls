package tls

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"io"
	"net"
)

type ClientHelloSpec struct {
	CipherSuites       []uint16    // nil => default
	CompressionMethods []uint8     // nil => no compression
	Extensions         []Extension // nil => no extensions

	DebugGreaseValues []uint16

	TLSVersMin uint16 // [1.0-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.0
	TLSVersMax uint16 // [1.2-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.2

	// GreaseStyle: currently only random
	// sessionID may or may not depend on ticket; nil => random
	GetSessionID func(ticket []byte) [32]byte

	// TLSFingerprintLink string // ?? link to tlsfingerprint.io for informational purposes
}

type UConfig struct {
	*Config
	HelloVersion uint16
	Extensions   []Extension
}

func (c *UConfig) AttemptHTTP2() bool {
	exts := ExtensionList(c.Extensions)
	protos := exts.FindByTypeOrDefault(&ALPNExtension{}).(*ALPNExtension).AlpnProtocols
	return protos[0] == "h2"
}

func (c *UConfig) Clone() *UConfig {
	return &UConfig{
		Config:     c.Config.Clone(),
		Extensions: cloneExtensions(c.Extensions),
	}
}

func cloneExtensions(exts []Extension) []Extension {
	var ext2 []Extension
	for _, ext := range exts {
		ext2 = append(ext2, ext.Clone())
	}

	return ext2
}

// ForUHttp creates a tls connection that conforms to http.TLSConn
func ForUHttp(conn net.Conn, ucfg *UConfig, cfg *tls.Config) (*UConn, error) {
	c := ucfg.Clone()
	c.ServerName = cfg.ServerName
	c.InsecureSkipVerify = cfg.InsecureSkipVerify

	return UClient(conn, c)
}

type UConn struct {
	*Conn
	config *UConfig

	greaseSeed [greaseLastIndex]uint16
}

func UClient(raw net.Conn, config *UConfig) (*UConn, error) {
	c := Client(raw, config.Config)
	uc := &UConn{
		Conn:   c,
		config: config,
	}

	c.parent = uc
	err := uc.setupGrease()

	return uc, err
}

func (u *UConn) HandshakeContext(ctx context.Context) error {
	return u.Conn.HandshakeContext(ctx)
}

func (u *UConn) ConnectionState() tls.ConnectionState {
	src := u.Conn.ConnectionState()

	return tls.ConnectionState{
		Version:                     src.Version,
		HandshakeComplete:           src.HandshakeComplete,
		DidResume:                   src.DidResume,
		CipherSuite:                 src.CipherSuite,
		NegotiatedProtocol:          src.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  src.NegotiatedProtocolIsMutual,
		ServerName:                  src.ServerName,
		PeerCertificates:            src.PeerCertificates,
		VerifiedChains:              src.VerifiedChains,
		SignedCertificateTimestamps: src.SignedCertificateTimestamps,
		OCSPResponse:                src.OCSPResponse,
		TLSUnique:                   src.TLSUnique,
	}
}

func (u *UConn) setupGrease() error {
	greaseBytes := make([]byte, 2*greaseLastIndex)

	_, err := io.ReadFull(u.config.rand(), greaseBytes)
	if err != nil {
		return errors.New("tls: short read from Rand: " + err.Error())
	}

	for i := range u.greaseSeed {
		u.greaseSeed[i] = binary.LittleEndian.Uint16(greaseBytes[2*i : 2*i+2])
	}

	if getGrease(u.greaseSeed, greaseExtension1) == getGrease(u.greaseSeed, greaseExtension2) {
		u.greaseSeed[greaseExtension2] ^= 0x1010
	}

	return nil
}

func (u *UConn) processServerHelloTLS13(hs *clientHandshakeStateTLS13) {
	if len(hs.hello.keyShares) > 1 {
		curveID := u.config.curvePreferences()[0]

		for i, ks := range hs.hello.keyShares {
			if ks.Group == curveID {
				hs.hello.keyShares = []KeyShare{hs.hello.keyShares[i]}
				break
			}
		}
	}
}

func (u *UConn) setupHello(m *clientHelloMsg) (err error) {

	if u.config.HelloVersion != 0 {
		m.vers = u.config.HelloVersion
	}

	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		// copy from handshake_messages.go:105
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.sessionId)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range m.cipherSuites {
				if suite == GreasePlaceholder {
					b.AddUint16(getGrease(u.greaseSeed, greaseCipher))
				} else {
					b.AddUint16(suite)
				}
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressionMethods)
		})

		if len(u.config.Extensions) > 0 {
			bOuter := b
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				var grease1 *GREASEExtension
				var grease2 *GREASEExtension

				for _, ext := range u.config.Extensions {

					switch v := ext.(type) {
					case *GREASEExtension:
						if grease1 == nil {
							grease1 = v
							grease1.Value = getGrease(u.greaseSeed, greaseExtension1)
						} else if grease2 == nil {
							grease2 = v
							grease2.Value = getGrease(u.greaseSeed, greaseExtension2)
						} else {
							err = errors.New("can only have 2 grease extensions max")
							return
						}

						b.AddUint16(v.Value)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							ext.MarshalBinary(b, nil, m)
						})

						continue
					case *PSKExtension:
						if len(m.pskIdentities) == 0 {
							continue // ignore if no pskIdentities
						}

						// todo: add support for session resumption
						continue
					case *PaddingExtension:
						if !v.WillPad {
							continue
						}

						outerLen := len(bOuter.BytesOrPanic()) - 2 // take 2 off for 16-bit length which is included in b
						padLen, ok := v.GetPaddingLen(outerLen + len(b.BytesOrPanic()))
						v.PaddingLen = padLen

						if !ok {
							continue
						}
					case *SNIExtension:
						v.ServerName = m.serverName
					case *KeyShareExtension:

						updated := []KeyShare{}

						for _, ks := range v.KeyShares {
							if IsGrease(uint16(ks.Group)) {
								// copy grease ones directly
								updated = append(updated, ks)
								continue
							}

							// don't use existing key share data b/c it's regenerated each time

							found := false

							// if .Data not provided, may need to pull from
							// pre-configured data (e.g. ECDHE) setup in conn.makeClientHell()
							for _, shr := range m.keyShares {
								if shr.Group == ks.Group {
									updated = append(updated, shr)
									found = true
									break
								}
							}

							if found {
								continue
							}

							if len(ks.Data) == 0 {
								err = errors.New("missing .Data for KeyShare " + fmt.Sprint(ks.Group) + " even after checking pre-computed")
								return
							}

							continue
						}

						v.KeyShares = updated
					case *ExtendedMasterSecretExtension:
						m.extendedMasterSecretSupported = true
					}

					b.AddUint16(ext.ID())
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						ext.MarshalBinary(b, u, m)
					})
				}
			})
		}
	})

	if err != nil {
		return
	}

	m.raw = b.BytesOrPanic()
	return
}
