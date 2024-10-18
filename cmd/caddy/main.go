package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/daaku/caddy-ssh"
)

func main() {
	caddycmd.Main()
}
