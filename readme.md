# caddy-ssh

A caddy plugin to proxy SSH over HTTP.

It tunnels SSH through Caddy over an ordinary HTTPS connection (port 443), so
it works on networks that only allow HTTP(S) and isn't an obvious SSH
connection on the wire. The handler proxies a request to SSH only when it
carries the header `X-Caddy-SSH: 1`; every other request falls through to the
next handler, so the same hostname can also serve a normal site — to anyone
opening the URL in a browser it's just that site. A bundled `caddy-ssh` client
is used as an OpenSSH `ProxyCommand`.

## Server (Caddyfile)

Build Caddy with the plugin:

```sh
xcaddy build --with github.com/daaku/caddy-ssh
```

The `ssh` directive is an HTTP handler, so it goes inside a `route` block. Its
optional argument is the backend SSH address (default `127.0.0.1:22`):

```caddyfile
example.com {
	route {
		ssh 127.0.0.1:22
		reverse_proxy 127.0.0.1:8080  # optional decoy site for other requests
	}
}
```

The address must be the directive argument; `ssh { 127.0.0.1:22 }` parses but
silently ignores it. Put `ssh` first so non-SSH requests reach the decoy.

## Client

Install the client and use it as an OpenSSH `ProxyCommand` in `~/.ssh/config`:

```sh
go install github.com/daaku/caddy-ssh/cmd/caddy-ssh@latest
```

```sshconfig
Host myserver
	HostName example.com
	User you
	ProxyCommand caddy-ssh https://example.com/
```

Then `ssh myserver`. Use `caddy-ssh -k …` to skip TLS verification.
