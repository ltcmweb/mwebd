package ledger

import (
	"encoding/binary"
	"io"

	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
)

type mwebAddInputState struct{ index int }

func (st *mwebAddInputState) request(ctx *TxContext) []byte {
	coin := ctx.Coins[st.index]
	buf := []byte{CLA_MWEB, INS_MWEB_ADD_INPUT, 0, 0, 0}
	buf = append(buf, coin.Blind[:]...)
	buf = binary.LittleEndian.AppendUint64(buf, coin.Value)
	buf = append(buf, coin.OutputId[:]...)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(ctx.AddrIndex[st.index]))
	buf = append(buf, coin.SharedSecret[:]...)
	return buf
}

func (st *mwebAddInputState) process(ctx *TxContext, r io.Reader) (txState, error) {
	result := struct {
		Features     wire.MwebInputFeatureBit
		OutputId     chainhash.Hash
		Commitment   mw.Commitment
		InputPubKey  mw.PublicKey
		OutputPubKey mw.PublicKey
		Signature    mw.Signature
	}{}
	err := binary.Read(r, binary.LittleEndian, &result)
	if err != nil {
		return nil, err
	}
	ctx.inputs = append(ctx.inputs, &wire.MwebInput{
		Features:     result.Features,
		OutputId:     result.OutputId,
		Commitment:   result.Commitment,
		InputPubKey:  &result.InputPubKey,
		OutputPubKey: result.OutputPubKey,
		Signature:    result.Signature,
	})
	if st.index++; st.index < len(ctx.Coins) {
		return st, nil
	} else if len(ctx.Recipients) > 0 {
		return &mwebAddOutputState{}, nil
	}
	return &mwebInitKernelState{}, nil
}
