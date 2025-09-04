package mwebd

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"

	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/ltcutil/psbt"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/mwebd/proto"
)

func (s *Server) PsbtCreate(ctx context.Context,
	req *proto.PsbtCreateRequest) (*proto.PsbtResponse, error) {

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(req.RawTx)); err != nil {
		return nil, err
	}

	p, err := psbt.NewFromUnsignedTx(&tx)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err = p.Serialize(&buf); err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{RawPsbt: buf.Bytes()}, nil
}

func (s *Server) PsbtAddInput(ctx context.Context,
	req *proto.PsbtAddInputRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.RawPsbt), false)
	if err != nil {
		return nil, err
	}

	outputId, err := hex.DecodeString(req.OutputId)
	if err != nil {
		return nil, err
	}

	output, err := s.fetchCoin(chainhash.Hash(outputId))
	if err != nil {
		return nil, err
	}

	coin, err := s.rewindOutput(output, (*mw.SecretKey)(req.ScanSecret))
	if err != nil {
		return nil, err
	}

	amount := ltcutil.Amount(coin.Value)

	p.Inputs = append(p.Inputs, psbt.PInput{
		MwebOutputId:     (*chainhash.Hash)(outputId),
		MwebAddressIndex: &req.AddressIndex,
		MwebAmount:       &amount,
		MwebSharedSecret: coin.SharedSecret,
		MwebCommit:       mw.SwitchCommit(coin.Blind, coin.Value),
	})

	s.addPeginIfNecessary(p)

	var buf bytes.Buffer
	if err = p.Serialize(&buf); err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{RawPsbt: buf.Bytes()}, nil
}

func (s *Server) getKernelIndex(p *psbt.Packet) (index int) {
	for _, pKernel := range p.Kernels {
		if pKernel.Signature == nil {
			break
		}
		index++
	}
	if index == len(p.Kernels) {
		fee := ltcutil.Amount(mweb.KernelWithStealthWeight * mweb.BaseMwebFee)
		p.Kernels = append(p.Kernels, psbt.PKernel{Fee: &fee})
	}
	return
}

func (s *Server) PsbtAddRecipient(ctx context.Context,
	req *proto.PsbtAddRecipientRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.RawPsbt), false)
	if err != nil {
		return nil, err
	}

	p.Outputs = append(p.Outputs, psbt.POutput{
		Amount: ltcutil.Amount(req.Value),
		StealthAddress: &mw.StealthAddress{
			Scan:  (*mw.PublicKey)(req.ScanPubkey),
			Spend: (*mw.PublicKey)(req.SpendPubkey),
		},
	})

	index := s.getKernelIndex(p)
	*p.Kernels[index].Fee += mweb.StandardOutputWeight * mweb.BaseMwebFee

	s.addPeginIfNecessary(p)

	var buf bytes.Buffer
	if err = p.Serialize(&buf); err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{RawPsbt: buf.Bytes()}, nil
}

func (s *Server) PsbtAddPegout(ctx context.Context,
	req *proto.PsbtAddPegoutRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.RawPsbt), false)
	if err != nil {
		return nil, err
	}

	index := s.getKernelIndex(p)
	txOut := wire.NewTxOut(req.Value, req.PkScript)
	p.Kernels[index].PegOuts = append(p.Kernels[index].PegOuts, txOut)

	fee := ltcutil.Amount(math.Ceil(float64(req.FeeRatePerKb) *
		float64(txOut.SerializeSize()) / 1000))
	fee += ltcutil.Amount(len(req.PkScript)+mweb.BytesPerWeight-1) /
		mweb.BytesPerWeight * mweb.BaseMwebFee
	*p.Kernels[index].Fee += fee

	s.addPeginIfNecessary(p)

	var buf bytes.Buffer
	if err = p.Serialize(&buf); err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{RawPsbt: buf.Bytes()}, nil
}

func (s *Server) addPeginIfNecessary(p *psbt.Packet) {
	var offset ltcutil.Amount

	for _, pInput := range p.Inputs {
		offset -= *pInput.MwebAmount
	}
	for _, pOutput := range p.Outputs {
		offset += pOutput.Amount
	}

	for _, pKernel := range p.Kernels {
		if pKernel.Fee != nil {
			offset += *pKernel.Fee
		}
		if pKernel.PeginAmount != nil {
			offset -= *pKernel.PeginAmount
		}
	}

	if offset > 0 {
		kernel := &p.Kernels[s.getKernelIndex(p)]
		if kernel.PeginAmount == nil {
			kernel.PeginAmount = new(ltcutil.Amount)
		}
		*kernel.PeginAmount += offset
	} else {
		for i, pKernel := range p.Kernels {
			if pKernel.Signature == nil && pKernel.PeginAmount != nil {
				if *pKernel.PeginAmount <= -offset {
					offset += *pKernel.PeginAmount
					p.Kernels[i].PeginAmount = nil
				} else {
					*p.Kernels[i].PeginAmount += offset
					break
				}
			}
		}
	}
}
