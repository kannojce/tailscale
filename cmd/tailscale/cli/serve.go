// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/util/mak"
)

var serveCmd = newServeCommand(&serveEnv{})

// newServeCommand returns a new "serve" subcommand using e as its environmment.
func newServeCommand(e *serveEnv) *ffcli.Command {
	return &ffcli.Command{
		Name:      "serve",
		ShortHelp: "TODO",
		ShortUsage: "serve <mount-point> {proxy|path|text} <arg>\n" +
			"  serve {show-config|https|tcp|ingress} <args>",
		LongHelp: strings.Join([]string{
			"EXAMPLES",
			"  - Proxy requests to a local web server on port 3000:",
			"    $ tailscale serve / proxy 3000",
			"",
			"  - Serve files (or directories) from a local path:",
			"    $ tailscale serve /some-file path /path/to/some-file",
			"",
			"  - Serve static text, mounted at \"/\":",
			"    $ tailscale serve / text \"Hello, world!\"",
		}, "\n"),
		Exec:    e.runServe,
		FlagSet: e.newFlags("serve", func(fs *flag.FlagSet) {}),
		Subcommands: []*ffcli.Command{
			{
				Name:      "show-config",
				Exec:      e.runServeShowConfig,
				ShortHelp: "show current serve config",
			},
			{
				Name:      "tcp",
				Exec:      e.runServeTCP,
				ShortHelp: "add or remove a TCP port forward",
				LongHelp: strings.Join([]string{
					"EXAMPLES",
					"  - Proxy TLS encrypted TCP packets to a local TCP server on port 5432:",
					"    $ tailscale serve tcp 5432",
					"",
					"  - Proxy raw, TLS-terminated TCP packets to a local TCP server on port 5432:",
					"    $ tailscale serve --terminate-tls tcp 5432",
				}, "\n"),
				FlagSet: e.newFlags("serve-tcp", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.terminateTLS, "terminate-tls", false, "terminate TLS before forwarding TCP connection")
				}),
			},
			{
				Name:      "ingress",
				Exec:      e.runServeIngress,
				ShortHelp: "enable or disable ingress",
				FlagSet:   e.newFlags("serve-ingress", func(fs *flag.FlagSet) {}),
			},
		},
	}
}

// serveEnv is the environment the serve command runs within. All I/O should be
// done via serveEnv methods so that it can be faked out for tests.
//
// It also contains the flags, as registered with newServeCommand.
type serveEnv struct {
	// flags
	terminateTLS bool

	// optional stuff for tests:
	testFlagOut        io.Writer
	testGetServeConfig func(context.Context) (*ipn.ServeConfig, error)
	testSetServeConfig func(context.Context, *ipn.ServeConfig) error
	testSelfDNSName    string
	testStdout         io.Writer
}

func (e *serveEnv) getSelfDNSName(ctx context.Context) (string, error) {
	if e.testSelfDNSName != "" {
		return e.testSelfDNSName, nil
	}
	st, err := getLocalClientStatus(ctx)
	if err != nil {
		return "", fmt.Errorf("getting client status: %w", err)
	}
	if st.Self == nil {
		return "", fmt.Errorf("no self node")
	}
	return strings.TrimSuffix(st.Self.DNSName, "."), nil
}

func getLocalClientStatus(ctx context.Context) (*ipnstate.Status, error) {
	st, err := localClient.Status(ctx)
	if err != nil {
		return nil, fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		printf("%s\n", description)
		os.Exit(1)
	}
	return st, nil
}

func (e *serveEnv) newFlags(name string, setup func(fs *flag.FlagSet)) *flag.FlagSet {
	onError, out := flag.ExitOnError, Stderr
	if e.testFlagOut != nil {
		onError, out = flag.ContinueOnError, e.testFlagOut
	}
	fs := flag.NewFlagSet(name, onError)
	fs.SetOutput(out)
	if setup != nil {
		setup(fs)
	}
	return fs
}

func (e *serveEnv) getServeConfig(ctx context.Context) (*ipn.ServeConfig, error) {
	if e.testGetServeConfig != nil {
		return e.testGetServeConfig(ctx)
	}
	return localClient.GetServeConfig(ctx)
}

func (e *serveEnv) setServeConfig(ctx context.Context, c *ipn.ServeConfig) error {
	if e.testSetServeConfig != nil {
		return e.testSetServeConfig(ctx, c)
	}
	return localClient.SetServeConfig(ctx, c)
}

func (e *serveEnv) stdout() io.Writer {
	if e.testStdout != nil {
		return e.testStdout
	}
	return os.Stdout
}

func (e *serveEnv) runServe(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return flag.ErrHelp
	}

	// Undocumented debug command (not using ffcli subcommands) to set raw
	// configs from stdin for now (2022-11-13).
	if len(args) == 1 && args[0] == "set-raw" {
		valb, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		sc := new(ipn.ServeConfig)
		if err := json.Unmarshal(valb, sc); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		return localClient.SetServeConfig(ctx, sc)
	}

	if len(args) != 3 {
		printf("error: invalid number of arguments\n\n")
		return flag.ErrHelp
	}

	h := new(ipn.HTTPHandler)
	mp, err := cleanMountPoint(args[0])
	if err != nil {
		return err
	}

	switch args[1] {
	case "path":
		fi, err := os.Stat(args[2])
		if err != nil {
			printf("error: invalid path: %v\n\n", err)
			return flag.ErrHelp
		}
		if fi.IsDir() && !strings.HasSuffix(mp, "/") {
			// dir mount points must end in /
			// for relative file links to work
			mp += "/"
		}
		fp, err := filepath.Abs(args[2])
		if err != nil {
			printf("error: invalid path: %v\n\n", err)
			return flag.ErrHelp
		}
		h.Path = fp
	case "proxy":
		t, err := expandProxyTarget(args[2])
		if err != nil {
			printf("error: %v\n\n", err)
			return flag.ErrHelp
		}
		h.Proxy = t
	case "text":
		h.Text = args[2]
	default:
		printf("error: unknown serve type %q\n\n", args[1])
		return flag.ErrHelp
	}

	cursc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	// web serves run HTTPS on port 443
	sc.TCP = map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}}

	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	var hp ipn.HostPort = ipn.HostPort(net.JoinHostPort(dnsName, "443"))
	if _, ok := sc.Web[hp]; !ok {
		mak.Set(&sc.Web, hp, new(ipn.WebServerConfig))
	}
	mak.Set(&sc.Web[hp].Handlers, mp, h)

	for k, v := range sc.Web[hp].Handlers {
		if v == h {
			continue
		}
		// If the new mount point ends in / and another mount point
		// shares the same prefix, remove the other handler.
		// (e.g. /foo/ overwrites /foo)
		// The opposite examples is also handled.
		if (strings.HasSuffix(mp, "/") && k == mp[:len(mp)-1]) ||
			(strings.HasSuffix(k, "/") && mp == k[:len(k)-1]) {
			delete(sc.Web[hp].Handlers, k)
			continue
		}
	}

	if reflect.DeepEqual(cursc, sc) {
		return nil
	}
	return e.setServeConfig(ctx, sc)
}

func cleanMountPoint(mp string) (string, error) {
	mp = strings.TrimLeft(mp, "/")
	mp = "/" + mp
	_, err := url.Parse(mp)
	if err != nil {
		return "", fmt.Errorf("invalid path segment: %v", err)
	}
	return mp, nil
}

func expandProxyTarget(target string) (string, error) {
	if allNumeric(target) {
		p, err := strconv.ParseUint(target, 10, 16)
		if p == 0 || err != nil {
			return "", fmt.Errorf("invalid port %q", target)
		}
		return "http://127.0.0.1:" + target, nil
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return "", fmt.Errorf("parsing url: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "https+insecure":
		// ok
	default:
		return "", fmt.Errorf("must be a URL starting with http://, https://, or https+insecure://")
	}
	host := u.Hostname()
	switch host {
	// TODO(shayne,bradfitz): do we want to do this?
	case "localhost", "127.0.0.1":
		host = "127.0.0.1"
	default:
		return "", fmt.Errorf("only localhost or 127.0.0.1 proxies are currently supported")
	}
	url := u.Scheme + "://" + host
	if u.Port() != "" {
		url += ":" + u.Port()
	}
	return url, nil
}

func allNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func (e *serveEnv) runServeShowConfig(ctx context.Context, args []string) error {
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	j, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	j = append(j, '\n')
	e.stdout().Write(j)
	return nil
}

func (e *serveEnv) runServeTCP(ctx context.Context, args []string) error {
	if len(args) != 1 {
		printf("error: invalid number of arguments\n\n")
		return flag.ErrHelp
	}

	portStr := args[0]
	p, err := strconv.ParseUint(portStr, 10, 16)
	if p == 0 || err != nil {
		printf("error: invalid port %q\n\n", portStr)
	}

	cursc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	sc.TCP = map[uint16]*ipn.TCPPortHandler{
		// TODO(shayne,bradfitz): we only going out with 443 for now?
		443: {TCPForward: "127.0.0.1:" + portStr},
	}

	if e.terminateTLS {
		dnsName, err := e.getSelfDNSName(ctx)
		if err != nil {
			return err
		}
		sc.TCP[443].TerminateTLS = dnsName
	}

	if reflect.DeepEqual(cursc, sc) {
		return nil
	}
	return e.setServeConfig(ctx, sc)
}

func (e *serveEnv) runServeIngress(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}
	var on bool
	switch args[0] {
	case "on", "off":
		on = args[0] == "on"
	default:
		return flag.ErrHelp
	}
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	var hp ipn.HostPort = ipn.HostPort(dnsName + ":443") // TODO(bradfitz,shayne): fix
	if on && sc != nil && sc.AllowIngress[hp] ||
		!on && (sc == nil || !sc.AllowIngress[hp]) {
		// Nothing to do.
		return nil
	}
	if sc == nil {
		sc = &ipn.ServeConfig{}
	}
	if on {
		mak.Set(&sc.AllowIngress, hp, true)
	} else {
		delete(sc.AllowIngress, hp)
	}
	return e.setServeConfig(ctx, sc)
}
