package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/ltcmweb/mwebd"
)

var (
	chain    = flag.String("c", "mainnet", "Chain")
	dataDir  = flag.String("d", ".", "Data directory")
	peer     = flag.String("p", "", "Connect to peer")
	bindAddr = flag.String("l", "127.0.0.1:12345", "Bind address")
	proxy    = flag.String("proxy", "", "Proxy address, \"socks5://127.0.0.1:9050\"")
)

func main() {
	flag.Parse()

	server, err := mwebd.NewServer(*chain, *dataDir, *peer, *proxy)
	if err != nil {
		log.Fatalln("Unable to start server:", err)
	}

	go waitForParent(server)
	if _, err = server.StartAddr(*bindAddr); err != nil {
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
