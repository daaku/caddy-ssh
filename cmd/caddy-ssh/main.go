package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	urlp "net/url"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
)

func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func closeRead(c net.Conn) error {
	if cw, ok := c.(interface{ CloseRead() error }); ok {
		return cw.CloseRead()
	}
	return nil
}

func run(ctx context.Context, insecure bool, url string) error {
	u, err := urlp.Parse(url)
	if err != nil {
		return err
	}
	var conn net.Conn
	addr := u.Host
	if u.Scheme == "https" {
		if u.Port() == "" {
			addr += ":443"
		}
		dialer := tls.Dialer{Config: &tls.Config{
			ServerName:         u.Hostname(),
			InsecureSkipVerify: insecure,
		}}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	} else {
		if u.Port() == "" {
			addr += ":80"
		}
		dialer := net.Dialer{}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("clientproxy: DialAndServe: %w", err)
	}
	defer conn.Close() // defensive close, ServeConn will handle this for us
	var b bytes.Buffer
	b.WriteString("GET ")
	b.WriteString(u.RequestURI())
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(u.Hostname())
	b.WriteString("\r\nX-Caddy-SSH: 1\r\n\r\n")
	if _, err := conn.Write(b.Bytes()); err != nil {
		return err
	}

	var fErr atomic.Value
	setErr := func(err error) {
		fErr.CompareAndSwap(nil, err)
	}

	close := func() {
		if err := conn.Close(); err != nil {
			setErr(fmt.Errorf("caddy-ssh: closing http connection: %w", err))
		}
		if err := os.Stdout.Close(); err != nil {
			setErr(fmt.Errorf("caddy-ssh: closing stdout: %w", err))
		}
		if err := os.Stdin.Close(); err != nil {
			setErr(fmt.Errorf("caddy-ssh: closing stdin: %w", err))
		}
	}
	var closeOnce sync.Once

	// close everything if the context is canceled, like a SIGTERM
	context.AfterFunc(ctx, func() {
		closeOnce.Do(close)
	})

	go func() {
		// we don't wait for this goroutine because reading from stdin is not
		// interruptable without shenanigans.
		if _, err := io.Copy(conn, os.Stdin); err != nil {
			setErr(fmt.Errorf("caddy-ssh: copying data to http from stdin: %w", err))
			closeOnce.Do(close)
			return
		}
		if err := closeWrite(conn); err != nil {
			setErr(fmt.Errorf("caddy-ssh: CloseWrite of http: %w", err))
			closeOnce.Do(close)
			return
		}
	}()

	if _, err := io.Copy(os.Stdout, conn); err != nil {
		setErr(fmt.Errorf("caddy-ssh: copying data to stdout from http: %w", err))
		closeOnce.Do(close)
	}
	if err := closeRead(conn); err != nil {
		setErr(fmt.Errorf("caddy-ssh: CloseRead of http: %w", err))
		closeOnce.Do(close)
	}

	closeOnce.Do(close)
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
