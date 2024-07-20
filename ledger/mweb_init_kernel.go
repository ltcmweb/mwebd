package ledger

import (
	"encoding/binary"
	"io"
)

type mwebInitKernelState struct{}

func (mwebInitKernelState) request(ctx *TxContext) []byte {
	buf := []byte{CLA_MWEB, INS_MWEB_SIGN_KERNEL, 1, 0, 0}
	buf = binary.LittleEndian.AppendUint64(buf, ctx.Fee)
	buf = binary.LittleEndian.AppendUint64(buf, ctx.Pegin)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(ctx.Pegouts)))
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	return buf
}

func (mwebInitKernelState) process(ctx *TxContext, r io.Reader) (txState, error) {
	if len(ctx.Pegouts) > 0 {
		return &mwebAddPegoutState{}, nil
	}
	return &mwebSignKernelState{}, nil
}
