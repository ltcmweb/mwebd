package main

import (
	"flag"
	"os"
	"time"

	"github.com/btcsuite/btclog"
	"github.com/ltcsuite/mwebd"
	"github.com/ltcsuite/neutrino"
)

var (
	chain   = flag.String("c", "mainnet", "Chain")
	dataDir = flag.String("d", ".", "Data directory")
	peer    = flag.String("p", "", "Connect to peer")
	port    = flag.Int("l", 12345, "Listen port")
)

func main() {
	flag.Parse()
	backend := btclog.NewBackend(os.Stdout)
	log := backend.Logger("LTCN")
	neutrino.UseLogger(log)

	server, err := mwebd.NewServer(*chain, *dataDir, *peer)
	if err != nil {
		log.Errorf("Unable to start server: %v", err)
		return
	}

	go waitForParent(server)
	if err = server.Start(*port); err != nil {
		log.Errorf("Failed to listen: %v", err)
	}
}

func waitForParent(server *mwebd.Server) {
	pid := os.Getppid()
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	if _, err = p.Wait(); err != nil {
		for os.Getppid() == pid {
			time.Sleep(time.Second)
		}
	}
	server.Stop()
}
