package main

import (
	"context"
	"crypto/tls"
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
	req, err := http.NewRequest("POST", url, stdin)
	if err != nil {
		return fmt.Errorf("clientproxy: NewRequest: %w", err)
	}
	req.Header.Set("X-Caddy-SSH", "1")
	res, err := t.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("clientproxy: RoundTrip: %w", err)
	}

	var fErr atomic.Value
	setErr := func(err error) {
		fErr.CompareAndSwap(nil, err)
	}

	close := func() {
		if err := res.Body.Close(); err != nil {
			setErr(fmt.Errorf("caddy-ssh: closing http response body: %w", err))
		}
		if err := os.Stdout.Close(); err != nil {
			setErr(fmt.Errorf("caddy-ssh: closing stdout: %w", err))
		}
		if err := stdin.Close(); err != nil {
			setErr(fmt.Errorf("caddy-ssh: closing stdin: %w", err))
		}
	}
	context.AfterFunc(ctx, close) // close everything if the context is canceled

	if _, err := io.Copy(os.Stdout, res.Body); err != nil {
		close()
		setErr(fmt.Errorf("caddy-ssh: copying data to stdout from http: %w", err))
	}

	close()
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
