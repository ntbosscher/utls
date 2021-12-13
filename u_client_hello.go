package tls

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"reflect"
)

type ClientHelloResult struct {
	// Vers is the max supported TLS version
	Vers                         uint16
	random                       []byte
	SessionId                    []byte
	CipherSuites                 []uint16
	CompressionMethods           []byte
	SecureRenegotiationSupported bool
	Extensions                   ExtensionList
}

func (m *ClientHelloResult) Unmarshal(data []byte) error {
	// mostly copied from handshake_messages.go:348
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.Vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.SessionId) {
		return errors.New("invalid version/random/sessionId")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return errors.New("invalid cipher suites")
	}
	m.CipherSuites = []uint16{}
	m.SecureRenegotiationSupported = false
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return errors.New("unable to decode cipher suite")
		}
		if suite == scsvRenegotiation {
			m.SecureRenegotiationSupported = true
		}
		m.CipherSuites = append(m.CipherSuites, unGrease(suite))
	}

	if !readUint8LengthPrefixed(&s, &m.CompressionMethods) {
		return errors.New("unable to decode compression methods")
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension Data
		return nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return errors.New("error decoding extension-block")
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return errors.New("unable to read extension/extension-data")
		}

		ext := GetExtensionForID(unGrease(extension))
		ext.UnmarshalBinary(&extData)
		m.Extensions = append(m.Extensions, ext)

		if !extData.Empty() {
			return fmt.Errorf("didn't decode extData properly for extension: %d", extension)
		}
	}

	return nil
}

type ExtensionList []Extension

func (e *ExtensionList) FindByTypeOrDefault(input Extension) Extension {
	typ := reflect.TypeOf(input)
	for _, item := range *e {
		if reflect.TypeOf(item).ConvertibleTo(typ) {
			return item
		}
	}

	return input
}

func (e *ExtensionList) MarshalJSON() ([]byte, error) {
	type encodeItem struct {
		ID     uint16
		Params interface{}
	}

	list := []*encodeItem{}

	for _, item := range []Extension(*e) {
		var id uint16

		if _, ok := item.(*GREASEExtension); ok {
			id = GreasePlaceholder
		} else {
			id = item.ID()
		}

		list = append(list, &encodeItem{ID: id, Params: item})
	}

	return json.Marshal(list)
}

func (e *ExtensionList) UnmarshalJSON(input []byte) error {
	type encodeItem struct {
		ID     uint16
		Params json.RawMessage
	}

	list := []*encodeItem{}
	err := json.Unmarshal(input, &list)
	if err != nil {
		return err
	}

	exts := []Extension{}

	for _, item := range list {
		ext := GetExtensionForID(item.ID)

		if err := json.Unmarshal(item.Params, ext); err != nil {
			return err
		}

		exts = append(exts, ext)
	}

	*e = ExtensionList(exts)
	return nil
}
