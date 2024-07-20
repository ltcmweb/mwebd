package ledger

import (
	"encoding/binary"
	"io"

	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
)

type mwebSignKernelState struct{}

func (mwebSignKernelState) request(ctx *TxContext) []byte {
	return []byte{CLA_MWEB, INS_MWEB_SIGN_KERNEL, 0, 0, 0, 0}
}

func (mwebSignKernelState) process(ctx *TxContext, r io.Reader) (txState, error) {
	result := struct {
		KernelOffset  mw.BlindingFactor
		StealthOffset mw.BlindingFactor
		Features      wire.MwebKernelFeatureBit
		KernelExcess  mw.Commitment
		StealthExcess mw.PublicKey
		Signature     mw.Signature
	}{}
	err := binary.Read(r, binary.LittleEndian, &result)
	if err != nil {
		return nil, err
	}
	ctx.Tx = &wire.MwebTx{
		KernelOffset:  result.KernelOffset,
		StealthOffset: result.StealthOffset,
		TxBody: &wire.MwebTxBody{
			Inputs:  ctx.inputs,
			Outputs: ctx.outputs,
			Kernels: []*wire.MwebKernel{{
				Features:      result.Features,
				Fee:           ctx.Fee,
				Pegin:         ctx.Pegin,
				Pegouts:       ctx.Pegouts,
				Excess:        result.KernelExcess,
				StealthExcess: result.StealthExcess,
				Signature:     result.Signature,
			}},
		},
	}
	ctx.Tx.TxBody.Sort()
	return nil, nil
}
