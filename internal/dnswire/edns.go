package dnswire

import (
	"encoding/binary"
	"fmt"
)

const (
	optionCookie        = 10 // RFC 7873
	optionExtendedError = 15 // RFC 8914
	flagDO              = 1 << 15
)

// EDNS holds the OPT record of a message (RFC 6891).
type EDNS struct {
	Version uint8
	UDPSize uint16
	DO      bool
	Flags   uint16 // all 16 bits, DO included
	Options []Option
}

// Option is one option of an OPT record, read as raw octets.
type Option struct {
	Code uint16
	Data []byte
}

type ExtendedError struct {
	InfoCode  uint16
	ExtraText string // raw octets
}

// readEDNS reads the OPT record r. Its options must fill its data exactly;
// their contents are left to the accessors.
func readEDNS(msg []byte, r rawRecord) (*EDNS, error) {
	if r.name.wire != "" {
		return nil, fmt.Errorf("%w: OPT owner %s is not the root", ErrMalformed, r.name)
	}
	e := &EDNS{
		Version: uint8(r.ttl >> 16),
		UDPSize: uint16(r.class),
		DO:      r.ttl&flagDO != 0,
		Flags:   uint16(r.ttl),
	}
	for off := r.dataOff; off < r.end; {
		if off+4 > r.end {
			return nil, fmt.Errorf("%w: OPT option at offset %d runs past the record data", ErrMalformed, off)
		}
		code := binary.BigEndian.Uint16(msg[off:])
		end := off + 4 + int(binary.BigEndian.Uint16(msg[off+2:]))
		if end > r.end {
			return nil, fmt.Errorf("%w: OPT option at offset %d runs past the record data", ErrMalformed, off)
		}
		e.Options = append(e.Options, Option{Code: code, Data: append([]byte(nil), msg[off+4:end]...)})
		off = end
	}
	return e, nil
}

// Cookie returns the client and server cookies. ok is true only when there
// is exactly one cookie option and its length is valid; server is nil when
// the option holds only a client cookie.
func (e *EDNS) Cookie() (client, server []byte, ok bool) {
	if e == nil {
		return nil, nil, false
	}
	var data []byte
	found := 0
	for _, o := range e.Options {
		if o.Code == optionCookie {
			data = o.Data
			found++
		}
	}
	if found != 1 || !validCookieLen(len(data)) {
		return nil, nil, false
	}
	if len(data) > 8 {
		server = data[8:]
	}
	return data[:8:8], server, true
}

// validCookieLen holds for a client cookie alone (8 octets) or a client
// cookie followed by a server cookie of 8 to 32 octets.
func validCookieLen(n int) bool {
	return n == 8 || 16 <= n && n <= 40
}

// ExtendedErrors returns every extended error option long enough to hold an
// info code, in message order.
func (e *EDNS) ExtendedErrors() []ExtendedError {
	if e == nil {
		return nil
	}
	var errs []ExtendedError
	for _, o := range e.Options {
		if o.Code == optionExtendedError && len(o.Data) >= 2 {
			errs = append(errs, ExtendedError{
				InfoCode:  binary.BigEndian.Uint16(o.Data),
				ExtraText: string(o.Data[2:]),
			})
		}
	}
	return errs
}
