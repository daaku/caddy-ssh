package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/sync/errgroup"
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

type writer struct {
	rc *http.ResponseController
	w  http.ResponseWriter
}

func newWriter(w http.ResponseWriter) *writer {
	return &writer{
		rc: http.NewResponseController(w),
		w:  w,
	}
}

func (w *writer) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err == nil {
		err = w.rc.Flush()
	}
	return n, err
}

func (h *Handler) ssh(w http.ResponseWriter, r *http.Request) error {
	if !r.ProtoAtLeast(2, 0) {
		return errors.New("ssh: must connect using HTTP/2 or higher")
	}
	wr := newWriter(w)
	addr := h.Addr
	if addr == "" {
		addr = "127.0.0.1:22"
	}
	sshConnC, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	sshConn := sshConnC.(*net.TCPConn)
	defer sshConn.Close() // backup close

	var eg errgroup.Group
	eg.Go(func() error {
		if _, err := io.Copy(sshConn, r.Body); err != nil {
			sshConn.Close()
			return fmt.Errorf("ssh: copying data to ssh from http: %w", err)
		}
		if err := sshConn.CloseWrite(); err != nil {
			sshConn.Close()
			return fmt.Errorf("ssh: CloseWrite of ssh: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		if _, err := io.Copy(wr, sshConn); err != nil {
			sshConn.Close()
			return fmt.Errorf("ssh: copying data to http from ssh: %w", err)
		}
		if err := sshConn.CloseRead(); err != nil {
			sshConn.Close()
			return fmt.Errorf("ssh: CloseRead of ssh: %w", err)
		}
		return nil
	})
	err = eg.Wait()
	if err == nil ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ENOTCONN) {
		return nil
	}
	return err
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
