package main

import (
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btclog"
	"github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcwallet/walletdb"
	_ "github.com/ltcsuite/ltcwallet/walletdb/bdb"
	"github.com/ltcsuite/mwebd"
	"github.com/ltcsuite/neutrino"
)

var (
	chain   = flag.String("c", "mainnet", "Chain")
	dataDir = flag.String("d", ".", "Data directory")
	peer    = flag.String("a", "", "Connect to peer")
	port    = flag.Int("p", 1234, "Listen port")
)

func main() {
	flag.Parse()
	backend := btclog.NewBackend(os.Stdout)
	log := backend.Logger("LTCN")
	neutrino.UseLogger(log)

	db, err := walletdb.Create(
		"bdb", filepath.Join(*dataDir, "neutrino.db"), true, time.Minute)
	if err != nil {
		log.Errorf("Unable to create Neutrino DB: %v", err)
		return
	}
	defer db.Close()

	chainParams := chaincfg.MainNetParams
	switch *chain {
	case chaincfg.TestNet4Params.Name:
		chainParams = chaincfg.TestNet4Params
	case chaincfg.RegressionNetParams.Name:
		chainParams = chaincfg.RegressionNetParams
	}

	cfg := neutrino.Config{
		DataDir:     *dataDir,
		Database:    db,
		ChainParams: chainParams,
	}
	if *peer != "" {
		cfg.AddPeers = []string{*peer}
	}
	chainService, err := neutrino.NewChainService(cfg)
	if err != nil {
		log.Errorf("Couldn't create Neutrino ChainService: %v", err)
		return
	}
	chainService.Start()

	server := &mwebd.Server{
		Port: *port,
		CS:   chainService,
		Log:  backend.Logger("RPCS"),
	}
	server.Start()
}
