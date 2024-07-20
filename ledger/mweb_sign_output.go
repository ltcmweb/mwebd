package ledger

import (
	"encoding/binary"
	"io"
)

type mwebSignOutputState struct{ index int }

func (st *mwebSignOutputState) request(ctx *TxContext) []byte {
	buf := []byte{CLA, INS_MWEB_SIGN_OUTPUT, 0, 0, 0}
	buf = append(buf, ctx.outputs[st.index].RangeProofHash[:]...)
	return buf
}

func (st *mwebSignOutputState) process(ctx *TxContext, r io.Reader) (txState, error) {
	output := ctx.outputs[st.index]
	err := binary.Read(r, binary.LittleEndian, &output.Signature)
	if err != nil {
		return nil, err
	}
	ctx.NewCoins[st.index].OutputId = output.Hash()
	if st.index++; st.index < len(ctx.Recipients) {
		return &mwebAddOutputState{st.index}, nil
	}
	return &mwebInitKernelState{}, nil
}
