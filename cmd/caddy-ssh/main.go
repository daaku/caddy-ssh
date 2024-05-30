package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	urlp "net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/daaku/errgroup"
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

func run(ctx context.Context, url string) error {
	ctx, cancel := context.WithCancel(ctx)

	// this will ensure our background goroutine below will be released if our
	// connection fails for reasons besides a context cancelation.
	defer cancel()

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
		dialer := tls.Dialer{Config: &tls.Config{ServerName: u.Hostname()}}
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
	var eg errgroup.Group
	eg.Add(2)

	close := func() {
		if err := conn.Close(); err != nil {
			eg.Error(fmt.Errorf("caddy-ssh: closing http connection: %w", err))
		}
		if err := os.Stdout.Close(); err != nil {
			eg.Error(fmt.Errorf("caddy-ssh: closing stdout: %w", err))
		}
		if err := os.Stdin.Close(); err != nil {
			eg.Error(fmt.Errorf("caddy-ssh: closing stdin: %w", err))
		}
	}
	var closeOnce sync.Once

	// close everything if the context is canceled, like a SIGTERM
	go func() {
		defer eg.Done()
		<-ctx.Done()
		closeOnce.Do(close)
	}()

	go func() {
		// we don't wait for this goroutine because reading from stdin is not
		// interruptable without shenanigans.
		// defer eg.Done()
		if _, err := io.Copy(conn, os.Stdin); err != nil {
			eg.Error(fmt.Errorf("caddy-ssh: copying data to http from stdin: %w", err))
			closeOnce.Do(close)
			return
		}
		if err := closeWrite(conn); err != nil {
			eg.Error(fmt.Errorf("caddy-ssh: CloseWrite of http: %w", err))
			closeOnce.Do(close)
			return
		}
	}()
	go func() {
		defer eg.Done()
		if _, err := io.Copy(os.Stdout, conn); err != nil {
			eg.Error(fmt.Errorf("caddy-ssh: copying data to stdout from http: %w", err))
			closeOnce.Do(close)
			return
		}
		if err := closeRead(conn); err != nil {
			eg.Error(fmt.Errorf("caddy-ssh: CloseRead of http: %w", err))
			closeOnce.Do(close)
			return
		}
	}()

	if err := eg.Wait(); err != nil {
		return err
	}
	closeOnce.Do(close)
	// we wait twice because close may also write an error to the errgroup
	return eg.Wait()
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
