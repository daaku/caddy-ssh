package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/http2"
)

func run(ctx context.Context, insecure bool, url string) error {
	t := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
	if err := syscall.SetNonblock(0, true); err != nil {
		return fmt.Errorf("clientproxy: SetNonblock: %w", err)
	}
	stdin := os.NewFile(0, "stdin")
	// Tie the request to the context so that cancellation, e.g. from SIGINT,
	// interrupts the round trip even while we're waiting for response headers.
	req, err := http.NewRequestWithContext(ctx, "POST", url, stdin)
	if err != nil {
		return fmt.Errorf("clientproxy: NewRequest: %w", err)
	}
	req.Header.Set("X-Caddy-SSH", "1")
	res, err := t.RoundTrip(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil // canceled, e.g. by SIGINT
		}
		return fmt.Errorf("clientproxy: RoundTrip: %w", err)
	}

	var fErr atomic.Value
	setErr := func(err error) {
		fErr.CompareAndSwap(nil, err)
	}

	// The HTTP transport closes the request body (stdin) too, so tolerate the
	// os.ErrClosed that a second Close reports.
	closeAll := func() {
		if err := res.Body.Close(); err != nil {
			setErr(fmt.Errorf("caddy-ssh: closing http response body: %w", err))
		}
		if err := os.Stdout.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			setErr(fmt.Errorf("caddy-ssh: closing stdout: %w", err))
		}
		if err := stdin.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			setErr(fmt.Errorf("caddy-ssh: closing stdin: %w", err))
		}
	}

	// Copy the response body to stdout in a goroutine so that a canceled
	// context can return even when the copy is blocked on a write to stdout
	// that cannot be interrupted, e.g. when the SSH client isn't reading. On
	// cancellation the process exits, tearing down the blocked copy.
	errCh := make(chan error, 1)
	go func() {
		_, err := io.Copy(os.Stdout, res.Body)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err != nil {
			setErr(fmt.Errorf("caddy-ssh: copying data to stdout from http: %w", err))
		}
		closeAll()
	case <-ctx.Done():
		return nil // canceled, e.g. by SIGINT
	}

	err, _ = fErr.Load().(error)
	return err
}

func main() {
	insecure := flag.Bool("k", false, "skip verifying TLS certificate")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *insecure, flag.Arg(0)); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
