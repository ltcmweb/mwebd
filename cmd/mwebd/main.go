package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/ltcmweb/mwebd"
)

var (
	chain   = flag.String("c", "mainnet", "Chain")
	dataDir = flag.String("d", ".", "Data directory")
	peer    = flag.String("p", "", "Connect to peer")
	port    = flag.Int("l", 12345, "Listen port")
)

func main() {
	flag.Parse()

	server, err := mwebd.NewServer(*chain, *dataDir, *peer)
	if err != nil {
		log.Fatalln("Unable to start server:", err)
	}

	go waitForParent(server)
	if _, err = server.Start(*port); err != nil {
		log.Fatalln("Failed to listen:", err)
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
