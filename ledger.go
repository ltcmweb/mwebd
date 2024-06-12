package mwebd

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/karalabe/hid"
)

type ledger struct{ hid.Device }

func newLedger() (*ledger, error) {
	ds, err := hid.Enumerate(0x2c97, 0)
	if err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, errors.New("device not found")
	}
	d, err := ds[0].Open()
	return &ledger{d}, err
}

func (l ledger) send(payload []byte) (resp []byte, err error) {
	const (
		Channel = 0x0101
		Tag     = 0x05
	)
	var (
		i      uint16
		p, r   []byte
		packet [64]byte
	)
	for i = 0; len(payload) > 0; i++ {
		p = packet[:]
		binary.BigEndian.PutUint16(p, Channel)
		p[2] = Tag
		binary.BigEndian.PutUint16(p[3:], i)
		p = p[5:]
		if i == 0 {
			binary.BigEndian.PutUint16(p, uint16(len(payload)))
			p = p[2:]
		}
		payload = payload[copy(p, payload):]
		if _, err = l.Write(packet[:]); err != nil {
			return
		}
	}
	for i = 0; i == 0 || len(r) > 0; i++ {
		var n int
		if n, err = l.Read(packet[:]); err != nil {
			return
		}
		err = errors.New("device read error")
		if n < len(packet) {
			return
		}
		p = packet[:]
		if binary.BigEndian.Uint16(p) != Channel {
			return
		}
		if p[2] != Tag {
			return
		}
		if binary.BigEndian.Uint16(p[3:]) != i {
			return
		}
		p = p[5:]
		if i == 0 {
			resp = make([]byte, binary.BigEndian.Uint16(p))
			p, r = p[2:], resp
		}
		r = r[copy(r, p):]
	}
	if sw := binary.BigEndian.Uint16(resp[len(resp)-2:]); sw != 0x9000 {
		return nil, fmt.Errorf("invalid status %x", sw)
	}
	return resp[:len(resp)-2], nil
}
