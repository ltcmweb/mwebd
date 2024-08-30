package mwebd

import (
	"crypto/ecdh"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/ltcmweb/coinswapd/onion"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
)

func TestOnion(t *testing.T) {
	const (
		totalFee  = 10
		feePerHop = 2
		inValue   = 1000
		outValue  = inValue - totalFee
	)

	var (
		randBytes = func() []byte {
			b := make([]byte, 32)
			rand.Read(b)
			return b
		}
		keychain = &mweb.Keychain{
			Scan:  (*mw.SecretKey)(randBytes()),
			Spend: (*mw.SecretKey)(randBytes()),
		}
		coin = &mweb.Coin{
			SpendKey: (*mw.SecretKey)(randBytes()),
			Blind:    (*mw.BlindingFactor)(randBytes()),
			Value:    inValue,
			OutputId: (*chainhash.Hash)(randBytes()),
		}
		recipient = &mweb.Recipient{
			Value:   outValue,
			Address: keychain.Address(0),
		}
		serverKeys []*ecdh.PrivateKey
	)

	input, output, kernelBlind, stealthBlind, err := makeCoinswapTx(coin, recipient)
	if err != nil {
		t.Fatal(err)
	}

	kernelBlinds := splitBlind(kernelBlind, 5)
	stealthBlinds := splitBlind(stealthBlind, 5)

	var hops []*onion.Hop
	for i := 0; i < 5; i++ {
		privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serverKeys = append(serverKeys, privKey)
		hops = append(hops, &onion.Hop{
			PubKey:       privKey.PublicKey(),
			KernelBlind:  *kernelBlinds[i],
			StealthBlind: *stealthBlinds[i],
			Fee:          feePerHop,
		})
	}
	hops[4].Output = output

	onion, err := onion.New(hops)
	if err != nil {
		t.Fatal(err)
	}
	onion.Sign(input, coin.SpendKey)

	var (
		inputCommit   = (*mw.Commitment)(onion.Input.Commitment).PubKey()
		outputCommit  = output.Commitment.PubKey()
		inputStealth  = (*mw.PublicKey)(onion.Input.InputPubKey).Add(&output.SenderPubKey)
		outputStealth = (*mw.PublicKey)(onion.Input.OutputPubKey)
	)

	for i := 0; i < 5; i++ {
		hop, onion2, err := onion.Peel(serverKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		onion = onion2

		if hop.KernelBlind != hops[i].KernelBlind {
			t.Fatal("kernel blind mismatch")
		}
		excess := mw.NewCommitment(&hop.KernelBlind, 0)
		inputCommit = inputCommit.Add(excess.PubKey())

		if hop.StealthBlind != hops[i].StealthBlind {
			t.Fatal("stealth blind mismatch")
		}
		sk := mw.SecretKey(hop.StealthBlind)
		outputStealth = outputStealth.Add(sk.PubKey())

		if hop.Fee != hops[i].Fee {
			t.Fatal("fee mismatch")
		}
		excess = mw.NewCommitment(&mw.BlindingFactor{}, hop.Fee)
		outputCommit = outputCommit.Add(excess.PubKey())

		if i < 4 {
			if hop.Output != nil {
				t.Fatal("unexpected output")
			}
		} else {
			if hop.Output == nil {
				t.Fatal("expected output")
			}
			if !reflect.DeepEqual(hop.Output, output) {
				t.Fatal("output mismatch")
			}
		}
	}

	if *inputCommit != *outputCommit {
		t.Fatal("commitment mismatch")
	}
	if *inputStealth != *outputStealth {
		t.Fatal("stealth sums unbalanced")
	}
}
