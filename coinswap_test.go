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
		commit     = &input.Commitment
		stealthSum = input.OutputPubKey.Sub(input.InputPubKey)
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
		commit = commit.Add(mw.NewCommitment(&hop.KernelBlind, 0))

		if hop.StealthBlind != hops[i].StealthBlind {
			t.Fatal("stealth blind mismatch")
		}
		sk := mw.SecretKey(hop.StealthBlind)
		stealthSum = stealthSum.Add(sk.PubKey())

		if hop.Fee != hops[i].Fee {
			t.Fatal("fee mismatch")
		}
		commit = commit.Sub(mw.NewCommitment(&mw.BlindingFactor{}, hop.Fee))

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

	if *commit != output.Commitment {
		t.Fatal("commitment mismatch")
	}
	if *stealthSum != output.SenderPubKey {
		t.Fatal("stealth sums unbalanced")
	}
}
