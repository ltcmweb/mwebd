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
	peer    = flag.String("p", "", "Connect to peer")
	port    = flag.Int("l", 12345, "Listen port")
	ppid    = flag.Int("ppid", 0, "Parent pid")
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

	cfg := neutrino.Config{
		DataDir:     *dataDir,
		Database:    db,
		ChainParams: chaincfg.MainNetParams,
	}
	switch *chain {
	case chaincfg.TestNet4Params.Name, "testnet":
		cfg.ChainParams = chaincfg.TestNet4Params
	case chaincfg.RegressionNetParams.Name:
		cfg.ChainParams = chaincfg.RegressionNetParams
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

	if *ppid > 0 {
		go func() {
			for os.Getppid() == *ppid {
				time.Sleep(time.Second)
			}
			server.Stop()
		}()
	}

	server.Start()
}
