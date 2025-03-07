package sip

import (
	"errors"
	"strconv"
	"strings"
)

func headerParserVia(headerName string, headerText string) (
	header Header, err error) {
	// sections := strings.Split(headerText, ",")
	h := ViaHeader{
		Params: HeaderParams{},
	}
	return &h, parseViaHeader(headerText, &h)
}

// parseViaHeader parses ViaHeader
// Note that although Via headers may contain a comma-separated list, RFC 3261 makes it clear that
// these should not be treated as separate logical Via headers, but as multiple values on a single
// Via header.
func parseViaHeader(headerText string, h *ViaHeader) error {
	h.Params = NewParams()

	state := viaStateProtocol
	str := headerText
	var ind, nextInd int
	var err error
	for state != nil {
		state, nextInd, err = state(h, str[ind:])
		if err != nil {

			// Fix the offset
			if _, ok := err.(errComaDetected); ok {
				err = errComaDetected(ind + nextInd)
			}
			return err
		}
		// If we alocated next hop this means we hit coma
		// if hop.Next != nil {
		// 	hop = h.Next
		// }
		ind += nextInd
	}
	return nil
}

type viaFSM func(h *ViaHeader, s string) (viaFSM, int, error)

func viaStateProtocol(h *ViaHeader, s string) (viaFSM, int, error) {
	ind := strings.IndexRune(s, '/')
	if ind < 0 {
		return nil, 0, errors.New("Malformed protocol name in Via header")
	}
	h.ProtocolName = strings.TrimSpace(s[:ind])
	return viaStateProtocolVersion, ind + 1, nil
}

func viaStateProtocolVersion(h *ViaHeader, s string) (viaFSM, int, error) {
	ind := strings.IndexRune(s, '/')
	if ind < 0 {
		return nil, 0, errors.New("Malformed protocol version in Via header")
	}
	h.ProtocolVersion = strings.TrimSpace(s[:ind])
	return viaStateProtocolTransport, ind + 1, nil
}

func viaStateProtocolTransport(h *ViaHeader, s string) (viaFSM, int, error) {
	ind := strings.IndexAny(s, " \t")
	if ind < 0 {
		return nil, 0, errors.New("Malformed transport in Via header")
	}
	h.Transport = strings.TrimSpace(s[:ind])
	return viaStateHost, ind + 1, nil
}

func viaStateHost(h *ViaHeader, s string) (viaFSM, int, error) {
	var colonInd int
	var endIndex int = len(s)
	var err error
loop:
	for i, c := range s {
		switch c {
		case ';':
			endIndex = i
			break loop
		case ':':
			colonInd = i
			// Uri has port
		}
	}

	if colonInd > 0 {
		h.Port, err = strconv.Atoi(s[colonInd+1 : endIndex])
		if err != nil {
			return nil, 0, nil
		}
		h.Host = strings.TrimSpace(s[:colonInd])
	} else {
		h.Host = strings.TrimSpace(s[:endIndex])
	}

	if endIndex == len(s) {
		return nil, 0, nil
	}

	// return nil, "", nil
	return viaStateParams, endIndex + 1, nil
}

func viaStateParams(h *ViaHeader, s string) (viaFSM, int, error) {
	var err error
	coma := strings.IndexRune(s, ',')
	if coma > 0 {
		// h.Params, _, err = ParseParams(s[:coma], ';', ';', 0, true, true)
		// h.Params, _, err = ParseParams(s[:coma], ';', ';')
		_, err = UnmarshalParams(s[:coma], ';', ',', h.Params)
		if err != nil {
			return nil, 0, err
		}
		// h.Next = &ViaHeader{
		// 	Params: HeaderParams{},
		// }
		return viaStateProtocol, coma, errComaDetected(coma)
	}

	// h.Params, _, err = ParseParams(s, ';', ';', 0, true, true)
	// h.Params, _, err = ParseParams(s, ';', ';')
	_, err = UnmarshalParams(s, ';', '\r', h.Params)
	return nil, 0, err
}
