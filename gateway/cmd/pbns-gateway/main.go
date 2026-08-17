package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"pbns.local/gateway/internal/gatewayapp"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := gatewayapp.Run(ctx, os.Args[1:], gatewayapp.Options{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
