package ledger

import (
	"encoding/binary"
	"io"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
)

type mwebAddOutputState struct{ index int }

func (st *mwebAddOutputState) request(ctx *TxContext) []byte {
	recipient := ctx.Recipients[st.index]
	pA, _ := secp.ParsePubKey(recipient.Address.A()[:])
	pB, _ := secp.ParsePubKey(recipient.Address.B()[:])
	buf := []byte{CLA_MWEB, INS_MWEB_ADD_OUTPUT, 0, 0, 0}
	buf = binary.LittleEndian.AppendUint64(buf, recipient.Value)
	buf = append(buf, pA.SerializeUncompressed()...)
	buf = append(buf, pB.SerializeUncompressed()...)
	return buf
}

func (st *mwebAddOutputState) process(ctx *TxContext, r io.Reader) (txState, error) {
	var (
		result struct {
			Commitment     mw.Commitment
			SenderPubKey   mw.PublicKey
			ReceiverPubKey mw.PublicKey
		}
		result2 struct {
			Blind  mw.BlindingFactor
			Shared mw.SecretKey
		}
	)
	if err := binary.Read(r, binary.LittleEndian, &result); err != nil {
		return nil, err
	}
	output := &wire.MwebOutput{
		Commitment:     result.Commitment,
		SenderPubKey:   result.SenderPubKey,
		ReceiverPubKey: result.ReceiverPubKey,
	}
	if err := output.Message.Deserialize(r); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &result2); err != nil {
		return nil, err
	}
	recipient := ctx.Recipients[st.index]
	mweb.SignOutput(output, recipient.Value, &result2.Blind, &mw.SecretKey{})
	ctx.outputs = append(ctx.outputs, output)
	ctx.NewCoins = append(ctx.NewCoins, &mweb.Coin{
		Blind:        &result2.Blind,
		Value:        recipient.Value,
		Address:      recipient.Address,
		SharedSecret: &result2.Shared,
	})
	return &mwebSignOutputState{st.index}, nil
}
