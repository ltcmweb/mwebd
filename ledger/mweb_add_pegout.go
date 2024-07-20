package ledger

import (
	"encoding/binary"
	"io"
)

type mwebAddPegoutState struct{ index int }

func (st *mwebAddPegoutState) request(ctx *TxContext) []byte {
	pegout := ctx.Pegouts[st.index]
	buf := []byte{CLA, INS_MWEB_SIGN_KERNEL, 0, 0, 0}
	buf = binary.LittleEndian.AppendUint64(buf, uint64(pegout.Value))
	buf = append(buf, byte(len(pegout.PkScript)))
	buf = append(buf, pegout.PkScript...)
	return buf
}

func (st *mwebAddPegoutState) process(ctx *TxContext, r io.Reader) (txState, error) {
	if st.index++; st.index < len(ctx.Pegouts) {
		return st, nil
	}
	return &mwebSignKernelState{}, nil
}
