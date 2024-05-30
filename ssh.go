package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/daaku/errgroup"
)

func init() {
	caddy.RegisterModule(&Handler{})
	httpcaddyfile.RegisterHandlerDirective("ssh", parseCaddyfile)
}

// Handler implements an HTTP handler that proxies connections to a ssh server.
type Handler struct {
	// Optional addr for SSH server. Defaults to 127.0.0.1:22.
	Addr string `json:"addr,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ssh",
		New: func() caddy.Module { return new(Handler) },
	}
}

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

func shouldLog(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	if errors.Is(err, syscall.ENOTCONN) {
		return false
	}
	return true
}

func (h *Handler) ssh(w http.ResponseWriter, _ *http.Request) error {
	rc := http.NewResponseController(w)
	if err := rc.EnableFullDuplex(); err != nil {
		return fmt.Errorf("ssh: must connect using HTTP/1.1: %w", err)
	}
	httpConn, buf, err := rc.Hijack()
	if err != nil {
		return fmt.Errorf("ssh: must connect using HTTP/1.1: %w", err)
	}
	defer httpConn.Close() // backup close
	if err := buf.Flush(); err != nil {
		return fmt.Errorf("ssh: unexpected flush error: %w", err)
	}
	addr := h.Addr
	if addr == "" {
		addr = "127.0.0.1:22"
	}
	sshConn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	defer sshConn.Close() // backup close

	var eg errgroup.Group
	eg.Add(2)

	close := func() {
		if err := httpConn.Close(); err != nil {
			eg.Error(fmt.Errorf("ssh: closing http connection: %w", err))
		}
		if err := sshConn.Close(); err != nil {
			eg.Error(fmt.Errorf("ssh: closing ssh connection: %w", err))
		}
	}
	var closeOnce sync.Once

	go func() {
		defer eg.Done()
		if buf.Reader.Buffered() > 0 {
			if _, err := io.Copy(sshConn, buf.Reader); err != nil {
				eg.Error(fmt.Errorf("ssh: copying buffered data to ssh from http: %w", err))
				closeOnce.Do(close)
				return
			}
		}
		if _, err := io.Copy(sshConn, httpConn); err != nil {
			eg.Error(fmt.Errorf("ssh: copying data to ssh from http: %w", err))
			closeOnce.Do(close)
			return
		}
		if err := closeWrite(sshConn); err != nil {
			eg.Error(fmt.Errorf("ssh: CloseWrite of ssh: %w", err))
			closeOnce.Do(close)
			return
		}
		if err := closeRead(httpConn); err != nil {
			eg.Error(fmt.Errorf("ssh: CloseRead of http: %w", err))
			closeOnce.Do(close)
			return
		}
	}()
	go func() {
		defer eg.Done()
		if _, err := io.Copy(httpConn, sshConn); err != nil {
			eg.Error(fmt.Errorf("ssh: copying data to http from ssh: %w", err))
			closeOnce.Do(close)
			return
		}
		if err := closeWrite(httpConn); err != nil {
			eg.Error(fmt.Errorf("ssh: CloseWrite of http: %w", err))
			closeOnce.Do(close)
			return
		}
		if err := closeRead(sshConn); err != nil {
			eg.Error(fmt.Errorf("ssh: CloseRead of ssh: %w", err))
			closeOnce.Do(close)
			return
		}
	}()

	if err := eg.Wait(); err != nil {
		if shouldLog(err) {
			return err
		}
		return nil
	}

	closeOnce.Do(close)

	// we wait twice because close may also write an error to the errgroup
	if err := eg.Wait(); err != nil {
		if shouldLog(err) {
			return err
		}
		return nil
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Header.Get("X-Caddy-SSH") != "1" { // need our special header
		return next.ServeHTTP(w, r)
	}
	return h.ssh(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	// if no argument, we're done
	if !d.NextArg() {
		return nil
	}

	// store the argument
	h.Addr = d.Val()
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
