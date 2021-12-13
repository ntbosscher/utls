package tls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"strconv"
	"strings"
)

type Extension interface {
	ID() uint16
	MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg)
	UnmarshalBinary(extData *cryptobyte.String) bool
	Clone() Extension
}

// RegisteredExtensions is a list of extensions we will decode
// in client-hello
var RegisteredExtensions = []Extension{
	&KeyShareExtension{},
	&GREASEExtension{},
	&SupportedCurvesExtension{},
	&SNIExtension{},
	&ExtendedMasterSecretExtension{},
	&RenegotiationInfoExtension{},
	&SupportedPointsExtension{},
	&ALPNExtension{},
	&SessionTicketExtension{},
	&StatusRequestExtension{},
	&SignatureAlgorithmsExtension{},
	&SCTExtension{},
	&PSKKeyExchangeModesExtension{},
	&PaddingExtension{},
	&SupportedVersionsExtension{},
	&PSKExtension{},
	&GenericExtension{},
}

func GetExtensionForID(id uint16) Extension {
	for _, ext := range RegisteredExtensions {
		if v, ok := ext.(*GREASEExtension); ok {
			if IsGrease(id) {
				c := v.Clone().(*GREASEExtension)
				c.Value = GreasePlaceholder
				return c
			}

			// don't call GREASEExtension{}.ID() otherwise bad things will happen
			continue
		}

		if ext.ID() == id {
			// clone to prevent data-races
			return ext.Clone()
		}
	}

	// fall back to generic
	ext := &GenericExtension{}
	ext.Id = id
	return ext
}

func (e *KeyShare) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"Group": fmt.Sprintf("0x%04x", uint16(e.Group)),
		"Data":  byteArrayToHex(e.Data),
	})
}

func (e *KeyShare) UnmarshalJSON(b []byte) error {
	val := map[string]string{}
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}

	ext := KeyShare{}

	ext.Group, err = parseCurveId(ciKey(val, "Group"))
	if err != nil {
		return err
	}

	ext.Data, err = parseHexBytes(ciKey(val, "Data"))
	if err != nil {
		return err
	}

	*e = ext

	return nil
}

func ciKey(input map[string]string, key string) string {
	rs, ok := input[key]
	if ok {
		return rs
	}

	rs, _ = input[strings.ToLower(key)]
	return rs
}

type KeyShareExtension struct {
	KeyShares []KeyShare
}

func (m *KeyShareExtension) ID() uint16 {
	return extensionKeyShare
}

func (m *KeyShareExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.keyShares = m.KeyShares

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, ks := range m.KeyShares {
			if ks.Group == GreasePlaceholder {
				b.AddUint16(getGrease(u.greaseSeed, greaseGroup))
			} else {
				b.AddUint16(uint16(ks.Group))
			}

			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(ks.Data)
			})
		}
	})
}

func (m *KeyShareExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	var clientShares cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&clientShares) {
		return false
	}
	for !clientShares.Empty() {
		var ks KeyShare
		if !clientShares.ReadUint16((*uint16)(&ks.Group)) ||
			!readUint16LengthPrefixed(&clientShares, &ks.Data) ||
			len(ks.Data) == 0 {
			return false
		}

		ks.Group = CurveID(unGrease(uint16(ks.Group)))
		m.KeyShares = append(m.KeyShares, ks)
	}

	return true
}

func (m *KeyShareExtension) Clone() Extension {
	return &KeyShareExtension{
		KeyShares: append([]KeyShare{}, m.KeyShares...),
	}
}

type GREASEExtension struct {
	// Value is auto-set during connection phase and follows
	// the BoringSSL algorithm
	// https://github.com/google/boringssl/blob/7d7554b6b3c79e707e25521e61e066ce2b996e4c/ssl/t1_lib.c#L2757
	Value uint16

	// Body is the responsibility of the caller
	Body []byte
}

func (e *GREASEExtension) ID() uint16 {
	panic("shouldn't ever call this, should rely on .Value")
}

func (e *GREASEExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	b.AddBytes(e.Body)
}

func (e *GREASEExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	// rely on caller setting .Value
	return extData.ReadBytes(&e.Body, len(*extData))
}

func (e *GREASEExtension) Clone() Extension {
	return &GREASEExtension{
		Value: e.Value,
		Body:  append([]byte{}, e.Body...),
	}
}

func (e *GREASEExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"value": fmt.Sprintf("0x%04x", e.Value),
		"body":  byteArrayToHex(e.Body),
	})
}

func (e *GREASEExtension) UnmarshalJSON(b []byte) error {

	val := map[string]string{}
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}

	ext := GREASEExtension{}
	ext.Value, err = parseUint16(val["value"])
	if err != nil {
		return err
	}

	ext.Body, err = parseHexBytes(val["body"])
	if err != nil {
		return err
	}

	*e = ext

	return nil
}

type SupportedCurvesExtension struct {
	Curves []CurveID
}

func (e *SupportedCurvesExtension) ID() uint16 {
	return extensionSupportedCurves
}

func (e *SupportedCurvesExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.supportedCurves = e.Curves

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, curve := range e.Curves {
			if curve == GreasePlaceholder {
				b.AddUint16(getGrease(u.greaseSeed, greaseGroup))
			} else {
				b.AddUint16(uint16(curve))
			}
		}
	})
}

func (e *SupportedCurvesExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	var curves cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
		return false
	}
	for !curves.Empty() {
		var curve uint16
		if !curves.ReadUint16(&curve) {
			return false
		}

		curve = unGrease(curve)

		e.Curves = append(e.Curves, CurveID(curve))
	}

	return true
}

func (e *SupportedCurvesExtension) Clone() Extension {
	return &SupportedCurvesExtension{
		Curves: append([]CurveID{}, e.Curves...),
	}
}

func (e *SupportedCurvesExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"curves": curveArrayToHex(e.Curves),
	})
}

func (e *SupportedCurvesExtension) UnmarshalJSON(b []byte) error {
	val := map[string]string{}
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}

	ext := SupportedCurvesExtension{}
	ext.Curves, err = parseCurveArray(val["curves"])
	if err != nil {
		return err
	}

	*e = ext

	return nil
}

type SNIExtension struct {
	ServerName string // not an array because go crypto/tls doesn't support multiple SNIs
}

func (e *SNIExtension) ID() uint16 {
	return extensionServerName
}

func (e *SNIExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.serverName = e.ServerName

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // name_type = host_name
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(e.ServerName))
		})
	})
}

func (e *SNIExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	var nameList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
		return false
	}
	for !nameList.Empty() {
		var nameType uint8
		var serverName cryptobyte.String
		if !nameList.ReadUint8(&nameType) ||
			!nameList.ReadUint16LengthPrefixed(&serverName) ||
			serverName.Empty() {
			return false
		}

		if len(e.ServerName) != 0 {
			// server name already set
			return false
		}

		e.ServerName = string(serverName)
		// An SNI value may not include a trailing dot.
		if strings.HasSuffix(e.ServerName, ".") {
			return false
		}
	}

	return true
}

func (e *SNIExtension) Clone() Extension {
	return &SNIExtension{
		ServerName: e.ServerName,
	}
}

type ExtendedMasterSecretExtension struct {
}

func (e *ExtendedMasterSecretExtension) ID() uint16 {
	return extensionExtendedMasterSecret
}

func (e *ExtendedMasterSecretExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	// no body
	return
}

func (e *ExtendedMasterSecretExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	// no body
	return true
}

func (e *ExtendedMasterSecretExtension) Clone() Extension {
	return &ExtendedMasterSecretExtension{}
}

type RenegotiationInfoExtension struct {
	// Renegotiation field limits how many times client will perform renegotiation: no limit, once, or never.
	// The extension still will be sent, even if Renegotiation is set to RenegotiateNever.
	Renegotiation RenegotiationSupport

	Data []byte
}

func (e *RenegotiationInfoExtension) ID() uint16 {
	return extensionRenegotiationInfo
}

func (e *RenegotiationInfoExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.secureRenegotiationSupported = true
	// is nil?
	//u.config.Config.Renegotiation = e.Renegotiation

	switch e.Renegotiation {
	case RenegotiateOnceAsClient:
		fallthrough
	case RenegotiateFreelyAsClient:
		// todo: something with handshake state
		//u.HandshakeState.Hello.SecureRenegotiationSupported = true
	case RenegotiateNever:
	default:
	}

	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(msg.secureRenegotiation)
	})
}

func (e *RenegotiationInfoExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	return extData.ReadBytes(&e.Data, len(*extData))
}

func (e *RenegotiationInfoExtension) Clone() Extension {
	return &RenegotiationInfoExtension{
		Renegotiation: e.Renegotiation,
	}
}

func (e *RenegotiationInfoExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"Data": byteArrayToHex(e.Data),
	})
}

func (e *RenegotiationInfoExtension) UnmarshalJSON(input []byte) error {

	mp := map[string]string{}
	err := json.Unmarshal(input, &mp)
	if err != nil {
		return err
	}

	ext := RenegotiationInfoExtension{}
	ext.Data, err = parseHexBytes(ciKey(mp, "Data"))

	if err != nil {
		return err
	}

	*e = ext
	return nil
}

type SupportedPointsExtension struct {
	SupportedPoints []uint8
}

func (e *SupportedPointsExtension) ID() uint16 {
	return extensionSupportedPoints
}

func (e *SupportedPointsExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.supportedPoints = e.SupportedPoints

	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.SupportedPoints)
	})
}

func (e *SupportedPointsExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	if !readUint8LengthPrefixed(extData, &e.SupportedPoints) ||
		len(e.SupportedPoints) == 0 {
		return false
	}

	return true
}

func (e *SupportedPointsExtension) Clone() Extension {
	return &SupportedPointsExtension{
		SupportedPoints: append([]uint8{}, e.SupportedPoints...),
	}
}

func (e *SupportedPointsExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"supportedPoints": uint8ArrayToHex(e.SupportedPoints),
	})
}

func (e *SupportedPointsExtension) UnmarshalJSON(b []byte) error {
	val := map[string]string{}
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}

	ext := SupportedPointsExtension{}
	ext.SupportedPoints, err = parseUint8s(val["supportedPoints"])
	if err != nil {
		return err
	}

	*e = ext

	return nil
}

type ALPNExtension struct {
	AlpnProtocols []string
}

func (e *ALPNExtension) ID() uint16 {
	return extensionALPN
}

func (e *ALPNExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.alpnProtocols = e.AlpnProtocols

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, proto := range e.AlpnProtocols {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(proto))
			})
		}
	})
}

func (e *ALPNExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	var protoList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
		return false
	}
	for !protoList.Empty() {
		var proto cryptobyte.String
		if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
			return false
		}
		e.AlpnProtocols = append(e.AlpnProtocols, string(proto))
	}

	return true
}

func (e *ALPNExtension) Clone() Extension {
	return &ALPNExtension{
		AlpnProtocols: append([]string{}, e.AlpnProtocols...),
	}
}

type SessionTicketExtension struct {
}

func (e *SessionTicketExtension) ID() uint16 {
	return extensionSessionTicket
}

func (e *SessionTicketExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.ticketSupported = true
	b.AddBytes(msg.sessionTicket)
}

func (e *SessionTicketExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	buf := []byte{}
	return extData.ReadBytes(&buf, len(*extData))
}

func (e *SessionTicketExtension) Clone() Extension {
	return &SessionTicketExtension{}
}

type StatusRequestExtension struct {
}

func (e *StatusRequestExtension) ID() uint16 {
	return extensionStatusRequest
}

func (e *StatusRequestExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.ocspStapling = true
	b.AddUint8(1)  // status_type = ocsp
	b.AddUint16(0) // empty responder_id_list
	b.AddUint16(0) // empty request_extensions
}

func (e *StatusRequestExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	var statusType uint8
	var ignored cryptobyte.String
	if !extData.ReadUint8(&statusType) ||
		!extData.ReadUint16LengthPrefixed(&ignored) ||
		!extData.ReadUint16LengthPrefixed(&ignored) {
		return false
	}
	// todo: do something with ocspStapling
	// m.ocspStapling = statusType == statusTypeOCSP

	return true
}

func (e *StatusRequestExtension) Clone() Extension {
	return &StatusRequestExtension{}
}

type SignatureAlgorithmsExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *SignatureAlgorithmsExtension) ID() uint16 {
	return extensionSignatureAlgorithms
}

func (e *SignatureAlgorithmsExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.supportedSignatureAlgorithms = e.SupportedSignatureAlgorithms

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, sigAlgo := range e.SupportedSignatureAlgorithms {
			b.AddUint16(uint16(sigAlgo))
		}
	})
}

func (e *SignatureAlgorithmsExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	var sigAndAlgs cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
		return false
	}
	for !sigAndAlgs.Empty() {
		var sigAndAlg uint16
		if !sigAndAlgs.ReadUint16(&sigAndAlg) {
			return false
		}
		e.SupportedSignatureAlgorithms = append(
			e.SupportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
	}

	return true
}

func (e *SignatureAlgorithmsExtension) Clone() Extension {
	return &SignatureAlgorithmsExtension{
		SupportedSignatureAlgorithms: append([]SignatureScheme{}, e.SupportedSignatureAlgorithms...),
	}
}

func (e *SignatureAlgorithmsExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"supportedSignatureAlgorithms": signatureArrayToHex(e.SupportedSignatureAlgorithms),
	})
}

func (e *SignatureAlgorithmsExtension) UnmarshalJSON(b []byte) error {
	val := map[string]string{}
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}

	ext := SignatureAlgorithmsExtension{}
	ext.SupportedSignatureAlgorithms, err = parseSignatures(val["supportedSignatureAlgorithms"])
	if err != nil {
		return err
	}

	*e = ext

	return nil
}

type SCTExtension struct {
}

func (e *SCTExtension) ID() uint16 {
	return extensionSCT
}

func (e *SCTExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.scts = true
}

func (e *SCTExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	// todo: do something with scts
	// scts = true
	return true
}

func (e *SCTExtension) Clone() Extension {
	return &SCTExtension{}
}

type PSKKeyExchangeModesExtension struct {
	Modes []uint8
}

func (e *PSKKeyExchangeModesExtension) ID() uint16 {
	return extensionPSKModes
}

func (e *PSKKeyExchangeModesExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	msg.pskModes = e.Modes

	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.Modes)
	})
}

func (e *PSKKeyExchangeModesExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	if !readUint8LengthPrefixed(extData, &e.Modes) {
		return false
	}

	return true
}

func (e *PSKKeyExchangeModesExtension) Clone() Extension {
	return &PSKKeyExchangeModesExtension{
		Modes: append([]uint8{}, e.Modes...),
	}
}

func (e *PSKKeyExchangeModesExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"modes": uint8ArrayToHex(e.Modes),
	})
}

func (e *PSKKeyExchangeModesExtension) UnmarshalJSON(b []byte) error {
	val := map[string]string{}
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}

	ext := PSKKeyExchangeModesExtension{}
	ext.Modes, err = parseUint8s(val["modes"])
	if err != nil {
		return err
	}

	*e = ext

	return nil
}

type PSKExtension struct {
}

func (e *PSKExtension) ID() uint16 {
	return extensionPreSharedKey
}

func (e *PSKExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, psk := range msg.pskIdentities {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(psk.label)
			})
			b.AddUint32(psk.obfuscatedTicketAge)
		}
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, binder := range msg.pskBinders {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(binder)
			})
		}
	})
}

func (e *PSKExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	var dump cryptobyte.String

	if !extData.ReadUint16LengthPrefixed(&dump) {
		return false
	}

	if !extData.ReadUint16LengthPrefixed(&dump) {
		return false
	}

	return true
}

func (e *PSKExtension) Clone() Extension {
	return &PSKKeyExchangeModesExtension{}
}

func (e *PSKExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{})
}

func (e *PSKExtension) UnmarshalJSON(b []byte) error {
	ext := PSKExtension{}
	*e = ext
	return nil
}

type PaddingExtension struct {
	PaddingLen int

	// WillPad = false disables
	WillPad bool

	// GetPaddingLen determines if/how much padding will be applied
	GetPaddingLen func(rawLength int) (paddingLen int, willPad bool)
}

func (e *PaddingExtension) ID() uint16 {
	return extensionPadding
}

func (e *PaddingExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	var buf []byte

	for i := 0; i < e.PaddingLen; i++ {
		buf = append(buf, 0x00)
	}

	b.AddBytes(buf)
}

func (e *PaddingExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	buf := []byte{}
	ok := extData.ReadBytes(&buf, len(*extData))

	e.PaddingLen = len(buf)
	e.WillPad = true

	return ok
}

func (e *PaddingExtension) Clone() Extension {
	return &PaddingExtension{
		PaddingLen:    e.PaddingLen,
		WillPad:       e.WillPad,
		GetPaddingLen: e.GetPaddingLen,
	}
}

func (e *PaddingExtension) MarshalJSON() ([]byte, error) {
	input := &struct {
		PaddingLen int
		WillPad    bool
	}{
		e.PaddingLen,
		e.WillPad,
	}
	return json.Marshal(input)
}

// BoringPaddingStyle pads the client hello packet
// https://github.com/google/boringssl/blob/7d7554b6b3c79e707e25521e61e066ce2b996e4c/ssl/t1_lib.c#L2803
func BoringPaddingStyle(rawLen int) (int, bool) {
	if rawLen > 0xff && rawLen < 0x200 {
		paddingLen := 0x200 - rawLen
		if paddingLen >= 4+1 {
			paddingLen -= 4
		} else {
			paddingLen = 1
		}
		return paddingLen, true
	}
	return 0, false
}

type SupportedVersionsExtension struct {
	Versions []uint16
}

func (e *SupportedVersionsExtension) ID() uint16 {
	return extensionSupportedVersions
}

func (e *SupportedVersionsExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, vers := range e.Versions {
			if vers == GreasePlaceholder {
				b.AddUint16(getGrease(u.greaseSeed, greaseVersion))
			} else {
				b.AddUint16(vers)
			}
		}
	})
}

func (e *SupportedVersionsExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	var versList cryptobyte.String
	if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
		return false
	}

	for !versList.Empty() {
		var vers uint16
		if !versList.ReadUint16(&vers) {
			return false
		}

		vers = unGrease(vers)

		e.Versions = append(e.Versions, vers)
	}

	return true
}

func (e *SupportedVersionsExtension) Clone() Extension {
	return &SupportedVersionsExtension{
		Versions: append([]uint16{}, e.Versions...),
	}
}

func (e *SupportedVersionsExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"versions": uint16ArrayToHex(e.Versions),
	})
}

func (e *SupportedVersionsExtension) UnmarshalJSON(b []byte) error {
	val := map[string]string{}
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}

	ext := SupportedVersionsExtension{}
	ext.Versions, err = parseUint16s(val["versions"])
	if err != nil {
		return err
	}

	*e = ext

	return nil
}

type GenericExtension struct {
	Id   uint16
	Data []byte
}

func (g *GenericExtension) ID() uint16 {
	return g.Id
}

func (g *GenericExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"Id":   g.Id,
		"Data": byteArrayToHex(g.Data),
	})
}

func (g *GenericExtension) UnmarshalJSON(b []byte) error {
	input := map[string]interface{}{}
	err := json.Unmarshal(b, &input)
	if err != nil {
		return err
	}

	rs := &GenericExtension{}
	for k, v := range input {
		switch strings.ToLower(k) {
		case "id":
			rs.Id = uint16(v.(float64))
		case "data":
			rs.Data, err = parseHexBytes(v.(string))
			if err != nil {
				return err
			}
		default:
			return errors.New("decoding GenericExtension: unrecognized key: '" + k + "'")
		}
	}

	*g = *rs
	return nil
}

func (g *GenericExtension) MarshalBinary(b *cryptobyte.Builder, u *UConn, msg *clientHelloMsg) {
	b.AddBytes(g.Data)
}

func (g *GenericExtension) UnmarshalBinary(extData *cryptobyte.String) bool {
	return extData.ReadBytes(&g.Data, len(*extData))
}

func (g *GenericExtension) Clone() Extension {
	return &GenericExtension{
		Id:   g.Id,
		Data: append([]byte{}, g.Data...),
	}
}

func parseUint16(input string) (uint16, error) {
	input = strings.TrimPrefix(input, "0x")

	val, err := strconv.ParseUint(input, 16, 16)
	if err != nil {
		return 0, err
	}
	return uint16(val), err
}

func parseHexBytes(input string) ([]byte, error) {
	if input == "" {
		return nil, nil
	}

	parts := strings.Split(input, " ")
	result := make([]byte, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimPrefix(part, "0x")

		val, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return nil, err
		}

		result = append(result, byte(val))
	}

	return result, nil
}

func byteArrayToHex(input []byte) string {
	wr := bytes.NewBuffer(nil)
	for _, b := range input {
		wr.WriteString(fmt.Sprintf("0x%02x ", b))
	}

	return strings.TrimSpace(wr.String())
}

func curveArrayToHex(input []CurveID) string {
	wr := bytes.NewBuffer(nil)
	for _, b := range input {
		wr.WriteString(fmt.Sprintf("0x%04x ", uint16(b)))
	}

	return strings.TrimSpace(wr.String())
}

func parseCurveId(input string) (CurveID, error) {
	val, err := parseUint16(input)
	return CurveID(val), err
}

func parseCurveArray(input string) ([]CurveID, error) {

	parts := strings.Split(input, " ")
	out := []CurveID{}

	for _, b := range parts {
		val, err := parseCurveId(b)
		if err != nil {
			return nil, err
		}

		out = append(out, val)
	}

	return out, nil
}

func signatureArrayToHex(input []SignatureScheme) string {
	wr := bytes.NewBuffer(nil)
	for _, b := range input {
		wr.WriteString(fmt.Sprintf("0x%04x ", uint16(b)))
	}

	return strings.TrimSpace(wr.String())
}

func parseSignatures(input string) ([]SignatureScheme, error) {
	parts := strings.Split(input, " ")
	out := []SignatureScheme{}

	for _, part := range parts {
		val, err := parseUint16(part)
		if err != nil {
			return nil, err
		}

		out = append(out, SignatureScheme(val))
	}

	return out, nil
}

func uint8ArrayToHex(input []uint8) string {
	wr := bytes.NewBuffer(nil)
	for _, b := range input {
		wr.WriteString(fmt.Sprintf("0x%02x ", b))
	}

	return strings.TrimSpace(wr.String())
}

func parseUint8s(input string) ([]uint8, error) {
	parts := strings.Split(input, " ")
	out := []uint8{}

	for _, item := range parts {
		item = strings.TrimPrefix(item, "0x")
		u, err := strconv.ParseUint(item, 16, 8)
		if err != nil {
			return nil, err
		}

		out = append(out, uint8(u))
	}

	return out, nil
}

func uint16ArrayToHex(input []uint16) string {
	wr := bytes.NewBuffer(nil)
	for _, b := range input {
		wr.WriteString(fmt.Sprintf("0x%04x ", b))
	}

	return strings.TrimSpace(wr.String())
}

func parseUint16s(input string) ([]uint16, error) {
	list := []uint16{}

	for _, item := range strings.Split(input, " ") {
		u, err := parseUint16(item)
		if err != nil {
			return nil, err
		}

		list = append(list, u)
	}

	return list, nil
}
