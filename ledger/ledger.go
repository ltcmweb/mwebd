package ledger

import (
	"bytes"
	"io"

	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/wire"
)

const (
	CLA_MWEB             = 0xeb
	INS_MWEB_ADD_INPUT   = 0x07
	INS_MWEB_ADD_OUTPUT  = 0x08
	INS_MWEB_SIGN_OUTPUT = 0x09
	INS_MWEB_SIGN_KERNEL = 0x0a
)

type (
	TxContext struct {
		Coins      []*mweb.Coin
		AddrIndex  []uint32
		Recipients []*mweb.Recipient
		Fee, Pegin uint64
		Pegouts    []*wire.TxOut

		state    txState
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

func (ctx *TxContext) Request() []byte {
	if ctx.state == nil {
		switch {
		case len(ctx.Coins) > 0:
			ctx.state = &mwebAddInputState{}
		case len(ctx.Recipients) > 0:
			ctx.state = &mwebAddOutputState{}
		default:
			ctx.state = &mwebInitKernelState{}
		}
	}
	req := ctx.state.request(ctx)
	req[4] = byte(len(req) - 5)
	return req
}

func (ctx *TxContext) Process(resp []byte) (err error) {
	if ctx.state != nil {
		ctx.state, err = ctx.state.process(ctx, bytes.NewReader(resp))
	}
	return
}
