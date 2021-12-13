package tls

// GREASE stinks with dead parrots, have to be super careful, and, if possible, not include GREASE
// https://github.com/google/boringssl/blob/1c68fa2350936ca5897a66b430ebaf333a0e43f5/ssl/internal.h
const (
	greaseCipher = iota
	greaseGroup
	greaseExtension1
	greaseExtension2
	greaseVersion
	greaseTicketExtension
	greaseLastIndex = greaseTicketExtension

	GreasePlaceholder = 0x0a0a
)

// getGrease generates next grease value
// will panic if ssl_grease_last_index[index] is out of bounds.
func getGrease(greaseSeed [greaseLastIndex]uint16, index int) uint16 {
	// GREASE value is back from deterministic to random.
	// https://github.com/google/boringssl/blob/a365138ac60f38b64bfc608b493e0f879845cb88/ssl/handshake_client.c#L530
	ret := uint16(greaseSeed[index])
	/* This generates a random value of the form 0xωaωa, for all 0 ≤ ω < 16. */
	ret = (ret & 0xf0) | 0x0a
	ret |= ret << 8
	return ret
}

func IsGrease(v uint16) bool {
	aVals := v&0x0A0A == 0x0A0A
	if !aVals {
		return false
	}

	lower := v & 0xF0
	upper := (v & 0xF000) >> 8
	return lower == upper
}

func unGrease(v uint16) uint16 {
	if IsGrease(v) {
		return GreasePlaceholder
	}

	return v
}
