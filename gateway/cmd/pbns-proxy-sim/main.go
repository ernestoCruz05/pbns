package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pbns.local/gateway/internal/proxysim"
)

var errConfiguration = errors.New("invalid proxy simulator configuration")

type options struct {
	listenPath string
	config     proxysim.Config
}

func parseArguments(arguments []string) (options, error) {
	flags := flag.NewFlagSet("pbns-proxy-sim", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var listenPath string
	var gatewayAddress string
	var serverName string
	var encodedSPKI string
	var fragmentSize int
	var delay time.Duration
	var dropAfter int64
	var duplicateOffset int64
	var duplicateLength int64
	var bitFlipOffset int64
	var dialTimeout time.Duration
	var handshakeTimeout time.Duration
	flags.StringVar(&listenPath, "listen", "", "Unix socket path")
	flags.StringVar(&gatewayAddress, "gateway", "", "gateway TCP address")
	flags.StringVar(&serverName, "server-name", "", "gateway TLS server name")
	flags.StringVar(&encodedSPKI, "spki-sha256", "", "gateway leaf SPKI SHA-256")
	flags.IntVar(&fragmentSize, "fragment-size", 0, "maximum write fragment")
	flags.DurationVar(&delay, "delay", 0, "delay after each fragment")
	flags.Int64Var(&dropAfter, "drop-after", -1, "inject a drop after this byte count")
	flags.Int64Var(&duplicateOffset, "duplicate-offset", -1, "first byte of duplicated range")
	flags.Int64Var(&duplicateLength, "duplicate-length", -1, "length of duplicated range")
	flags.Int64Var(&bitFlipOffset, "bit-flip-offset", -1, "byte offset whose low bit is flipped")
	flags.DurationVar(&dialTimeout, "dial-timeout", 5*time.Second, "gateway dial timeout")
	flags.DurationVar(&handshakeTimeout, "handshake-timeout", 5*time.Second, "TLS handshake timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return options{}, errConfiguration
	}
	spki, err := hex.DecodeString(encodedSPKI)
	if err != nil || len(spki) != 32 || listenPath == "" || gatewayAddress == "" || serverName == "" ||
		dropAfter < -1 || duplicateOffset < -1 || duplicateLength < -1 || bitFlipOffset < -1 ||
		(duplicateOffset == -1) != (duplicateLength == -1) {
		return options{}, errConfiguration
	}
	faults := proxysim.Faults{FragmentSize: fragmentSize, Delay: delay}
	if dropAfter >= 0 {
		value := dropAfter
		faults.DropAfter = &value
	}
	if duplicateOffset >= 0 {
		faults.Duplicate = &proxysim.ByteRange{Offset: duplicateOffset, Length: duplicateLength}
	}
	if bitFlipOffset >= 0 {
		value := bitFlipOffset
		faults.BitFlipOffset = &value
	}
	config := proxysim.Config{
		GatewayAddress:   gatewayAddress,
		ServerName:       serverName,
		PinnedSPKI:       spki,
		DialTimeout:      dialTimeout,
		HandshakeTimeout: handshakeTimeout,
		Upstream:         faults,
		Downstream:       faults,
	}
	if _, err := proxysim.New(config); err != nil {
		return options{}, errConfiguration
	}
	return options{listenPath: listenPath, config: config}, nil
}

func run(ctx context.Context, arguments []string) error {
	if ctx == nil {
		return errConfiguration
	}
	options, err := parseArguments(arguments)
	if err != nil {
		return err
	}
	proxy, err := proxysim.New(options.config)
	if err != nil {
		return errConfiguration
	}
	if info, statErr := os.Lstat(options.listenPath); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%w: listen path exists", errConfiguration)
		}
		if removeErr := os.Remove(options.listenPath); removeErr != nil {
			return fmt.Errorf("remove stale Unix socket: %w", removeErr)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect Unix socket: %w", statErr)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: options.listenPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen on Unix socket: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	defer listener.Close()
	if err := os.Chmod(options.listenPath, 0o600); err != nil {
		return fmt.Errorf("restrict Unix socket: %w", err)
	}
	return proxy.Serve(ctx, listener)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
