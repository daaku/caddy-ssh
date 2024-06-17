package ssh

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/daaku/http2nc"
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

func (h *Handler) ssh(w http.ResponseWriter, r *http.Request) error {
	addr := h.Addr
	if addr == "" {
		addr = "127.0.0.1:22"
	}
	return http2nc.DialConnect(w, r, addr)
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
