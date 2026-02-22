package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/foursixnine/pass-exporter/internal/exporter"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	clean_exit := exporter.Export(ctx)
	if clean_exit {
		os.Exit(0)
	} else {
		os.Exit(1)
	}

}
