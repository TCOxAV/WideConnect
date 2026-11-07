// Command wcd is the WideConnect desktop daemon.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/internal/server"
)

func main() {
	addr := flag.String("addr", ":7777", "address to listen on")
	configDir := flag.String("config", "", "config directory (default: user config dir)")
	flag.Parse()

	dir := *configDir
	if dir == "" {
		var err error
		dir, err = identity.DefaultDir()
		if err != nil {
			log.Fatalf("config: %v", err)
		}
	}

	id, err := identity.LoadOrCreate(dir)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	log.Printf("device id: %s", id)

	// Cancel the context on Ctrl+C or SIGTERM for a clean shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(*addr, id)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
	log.Println("shutdown complete")
}
