package main

import (
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

func main() {
	dataDir := "regtest"

	backend := btclog.NewBackend(os.Stdout)
	log := backend.Logger("LTCN")
	neutrino.UseLogger(log)

	db, err := walletdb.Create(
		"bdb", filepath.Join(dataDir, "neutrino.db"), true, time.Minute)
	if err != nil {
		log.Errorf("Unable to create Neutrino DB: %v", err)
		return
	}
	defer db.Close()

	chainService, err := neutrino.NewChainService(
		neutrino.Config{
			DataDir:     dataDir,
			Database:    db,
			ChainParams: chaincfg.RegressionNetParams,
			AddPeers:    []string{"127.0.0.1:19444"},
		})
	if err != nil {
		log.Errorf("Couldn't create Neutrino ChainService: %v", err)
		return
	}
	chainService.Start()

	server := &mwebd.Server{
		Port: 1234,
		CS:   chainService,
		Log:  backend.Logger("RPCS"),
	}
	server.Start()
}
