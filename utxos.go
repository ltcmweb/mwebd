package mwebd

import (
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/mwebd/proto"
)

type utxoStreamer struct {
	s      *Server
	scan   *mw.SecretKey
	ch     chan *proto.Utxo
	quit   chan struct{}
	lfs    *mweb.Leafset
	leaves map[uint64]bool
	init   bool
}

func (s *Server) newUtxoStreamer(scanSecret *mw.SecretKey) *utxoStreamer {
	return &utxoStreamer{
		s:      s,
		scan:   scanSecret,
		ch:     make(chan *proto.Utxo),
		quit:   make(chan struct{}),
		leaves: map[uint64]bool{},
	}
}

func (u *utxoStreamer) notify(lfs *mweb.Leafset,
	utxos []*proto.Utxo, leaves []uint64) {

	if !u.init {
		select {
		case u.ch <- &proto.Utxo{}:
			u.init = true
		case <-u.quit:
			return
		}
	}
	for _, utxo := range utxos {
		select {
		case u.ch <- utxo:
		case <-u.quit:
		}
	}
	for _, leaf := range leaves {
		u.leaves[leaf] = true
	}
	if lfs != nil {
		i := 0
		for i < len(u.lfs.Bits) && i < len(lfs.Bits) &&
			u.lfs.Bits[i] == lfs.Bits[i] {
			i++
		}
		leaf := uint64(i * 8)
		for leaves := []uint64{}; leaf < lfs.Size; leaf++ {
			if !u.lfs.Contains(leaf) && lfs.Contains(leaf) && !u.leaves[leaf] {
				leaves = append(leaves, leaf)
			}
			if len(leaves) == 1000 || leaf == lfs.Size-1 {
				utxos, err := u.s.cs.MwebCoinDB.FetchLeaves(leaves)
				if err != nil {
					break
				}
				for _, utxo := range u.s.filterUtxos(u.scan, utxos) {
					select {
					case u.ch <- utxo:
					case <-u.quit:
					}
				}
				leaves = leaves[:0]
			}
		}
		u.lfs = lfs
		clear(u.leaves)
	}
}
