package ledger

import (
	"encoding/binary"
	"io"
)

type mwebGetPublicKeyState struct{}

func (mwebGetPublicKeyState) request(ctx *TxContext) []byte {
	buf := []byte{CLA_MWEB, INS_MWEB_GET_PUBLIC_KEY, 0, 0, 0, byte(len(ctx.HdPath))}
	for _, p := range ctx.HdPath {
		buf = binary.BigEndian.AppendUint32(buf, p)
	}
	return buf
}

func (mwebGetPublicKeyState) process(ctx *TxContext, r io.Reader) (txState, error) {
	if len(ctx.Coins) > 0 {
		return &mwebAddInputState{}, nil
	} else if len(ctx.Recipients) > 0 {
		return &mwebAddOutputState{}, nil
	}
	return &mwebInitKernelState{}, nil
}
