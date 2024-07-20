package ledger

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/karalabe/hid"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/wire"
)

type Ledger struct{ hid.Device }

func NewLedger() (*Ledger, error) {
	ds, err := hid.Enumerate(0x2c97, 0)
	if err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, errors.New("device not found")
	}
	d, err := ds[0].Open()
	return &Ledger{d}, err
}

func (l Ledger) Send(payload []byte) (resp []byte, err error) {
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

const (
	CLA_MWEB                = 0xeb
	INS_MWEB_GET_PUBLIC_KEY = 0x05
	INS_MWEB_ADD_INPUT      = 0x07
	INS_MWEB_ADD_OUTPUT     = 0x08
	INS_MWEB_SIGN_OUTPUT    = 0x09
	INS_MWEB_SIGN_KERNEL    = 0x0a
)

type (
	TxContext struct {
		HdPath     []uint32
		Coins      []*mweb.Coin
		AddrIndex  []uint32
		Recipients []*mweb.Recipient
		Fee, Pegin uint64
		Pegouts    []*wire.TxOut

		inputs   []*wire.MwebInput
		outputs  []*wire.MwebOutput
		NewCoins []*mweb.Coin
		Tx       *wire.MwebTx
	}
	txState interface {
		request(*TxContext) []byte
		process(*TxContext, io.Reader) (txState, error)
	}
)

func (ctx *TxContext) Run() (err error) {
	l, err := NewLedger()
	if err != nil {
		return
	}
	defer l.Close()

	for st := txState(&mwebGetPublicKeyState{}); ; {
		buf := st.request(ctx)
		buf[4] = byte(len(buf) - 5)
		if buf, err = l.Send(buf); err != nil {
			return
		}
		if st, err = st.process(ctx, bytes.NewReader(buf)); err != nil {
			return
		}
		if ctx.Tx != nil {
			return
		}
	}
}
