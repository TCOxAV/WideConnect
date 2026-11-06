// Command wcd is the WideConnect desktop daemon.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/TCOxAV/WideConnect/internal/server"
)

func main() {
	addr := flag.String("addr", ":7777", "address to listen on")
	flag.Parse()

	// Cancel the context on Ctrl+C or SIGTERM for a clean shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(*addr)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
	log.Println("shutdown complete")
}
