// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestServeConfigMutations(t *testing.T) {
	// Stateful mutations, starting from an empty config.
	type step struct {
		command []string                       // serve args; nil means no command to run (only reset)
		reset   bool                           // if true, reset all ServeConfig state
		want    *ipn.ServeConfig               // non-nil means we want a save of this value
		wantErr func(error) (badErrMsg string) // nil means no error is wanted
		line    int                            // line number of addStep call, for error messages
	}
	var steps []step
	add := func(s step) {
		_, _, s.line, _ = runtime.Caller(1)
		steps = append(steps, s)
	}

	// ingress
	add(step{reset: true})
	add(step{
		command: cmd("ingress on"),
		want:    &ipn.ServeConfig{AllowIngress: map[ipn.HostPort]bool{"foo:443": true}},
	})
	add(step{
		command: cmd("ingress on"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("ingress off"),
		want:    &ipn.ServeConfig{AllowIngress: map[ipn.HostPort]bool{}},
	})
	add(step{
		command: cmd("ingress off"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("ingress"),
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})

	// https
	add(step{reset: true})
	add(step{
		command: cmd("/ proxy 0"), // invalid port, too low
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})
	add(step{
		command: cmd("/ proxy 65536"), // invalid port, too high
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})
	add(step{
		command: cmd("/ proxy somehost"), // invalid host
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})
	add(step{
		command: cmd("/ proxy http://otherhost"), // invalid host
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})
	add(step{
		command: cmd("/ proxy httpz://127.0.0.1"), // invalid scheme
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})
	add(step{
		command: cmd("/ proxy 3000"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{
		command: cmd("bar proxy https://127.0.0.1:8443"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/":    {Proxy: "http://127.0.0.1:3000"},
					"/bar": {Proxy: "https://127.0.0.1:8443"},
				}},
			},
		},
	})
	add(step{
		command: cmd("bar proxy https://127.0.0.1:8443"),
		reset:   false,
		want:    nil, // nothing to save
	})
	add(step{reset: true})
	add(step{
		command: cmd("/ proxy https+insecure://127.0.0.1:3001"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "https+insecure://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{reset: true})
	add(step{
		command: cmd("////foo proxy localhost:3000"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/foo": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})

	// tcp
	add(step{reset: true})
	add(step{
		command: cmd("tcp 5432"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {TCPForward: "127.0.0.1:5432"},
			},
		},
	})
	add(step{
		command: cmd("tcp -terminate-tls 8443"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:8443",
					TerminateTLS: "foo",
				},
			},
		},
	})
	add(step{
		command: cmd("tcp -terminate-tls 8443"),
		reset:   false,
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("tcp --terminate-tls 8444"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:8444",
					TerminateTLS: "foo",
				},
			},
		},
	})
	add(step{
		command: cmd("tcp -terminate-tls=false 8445"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {TCPForward: "127.0.0.1:8445"},
			},
		},
	})

	// text
	add(step{reset: true})
	add(step{
		command: cmd("/ text hello"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Text: "hello"},
				}},
			},
		},
	})

	// path
	td := t.TempDir()
	writeFile := func(suffix, contents string) {
		if err := os.WriteFile(filepath.Join(td, suffix), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	add(step{reset: true})
	writeFile("foo", "this is foo")
	add(step{
		command: cmd("/ path " + filepath.Join(td, "foo")),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Path: filepath.Join(td, "foo")},
				}},
			},
		},
	})
	os.MkdirAll(filepath.Join(td, "subdir"), 0700)
	writeFile("subdir/file-a", "this is A")
	add(step{
		command: cmd("/some/where path " + filepath.Join(td, "subdir/file-a")),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/":           {Path: filepath.Join(td, "foo")},
					"/some/where": {Path: filepath.Join(td, "subdir/file-a")},
				}},
			},
		},
	})
	add(step{
		command: cmd("/ path missing"),
		reset:   false,
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})
	add(step{reset: true})
	add(step{
		command: cmd("/ path " + filepath.Join(td, "subdir")),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Path: filepath.Join(td, "subdir/")},
				}},
			},
		},
	})

	// combos
	add(step{reset: true})
	add(step{
		command: cmd("/ proxy 3000"),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{
		command: cmd("ingress on"),
		want: &ipn.ServeConfig{
			AllowIngress: map[ipn.HostPort]bool{"foo:443": true},
			TCP:          map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})

	// tricky steps
	add(step{reset: true})
	add(step{
		command: cmd("/dir path " + filepath.Join(td, "subdir")),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/dir/": {Path: filepath.Join(td, "subdir/")},
				}},
			},
		},
	}) // a directory with a trailing slash mount point
	add(step{
		command: cmd("/dir path " + filepath.Join(td, "foo")),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/dir": {Path: filepath.Join(td, "foo")},
				}},
			},
		},
	}) // this should overwrite the previous one
	add(step{reset: true})
	add(step{
		command: cmd("/dir path " + filepath.Join(td, "foo")),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/dir": {Path: filepath.Join(td, "foo")},
				}},
			},
		},
	}) // a file without a trailing slash mount point
	add(step{
		command: cmd("/dir path " + filepath.Join(td, "subdir")),
		reset:   false,
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/dir/": {Path: filepath.Join(td, "subdir/")},
				}},
			},
		},
	}) // this should overwrite the previous one

	// And now run the steps above.
	var current *ipn.ServeConfig
	for i, st := range steps {
		if st.reset {
			t.Logf("Executing step #%d, line %v: [reset]", i, st.line)
			current = nil
		}
		if st.command == nil {
			continue
		}
		t.Logf("Executing step #%d, line %v: %q ... ", i, st.line, st.command)

		var stdout bytes.Buffer
		var flagOut bytes.Buffer
		var newState *ipn.ServeConfig
		e := &serveEnv{
			testFlagOut: &flagOut,
			testStdout:  &stdout,
			testGetServeConfig: func(context.Context) (*ipn.ServeConfig, error) {
				return current, nil
			},
			testSetServeConfig: func(_ context.Context, c *ipn.ServeConfig) error {
				newState = c
				return nil
			},
			testSelfDNSName: "foo",
		}
		cmd := newServeCommand(e)
		err := cmd.ParseAndRun(context.Background(), st.command)
		if flagOut.Len() > 0 {
			t.Logf("flag package output: %q", flagOut.Bytes())
		}
		if err != nil {
			if st.wantErr == nil {
				t.Fatalf("step #%d, line %v: unexpected error: %v", i, st.line, err)
			}
			if bad := st.wantErr(err); bad != "" {
				t.Fatalf("step #%d, line %v: unexpected error: %v", i, st.line, bad)
			}
			continue
		}
		if st.wantErr != nil {
			t.Fatalf("step #%d, line %v: got success (saved=%v), but wanted an error", i, st.line, newState != nil)
		}
		if !reflect.DeepEqual(newState, st.want) {
			t.Fatalf("[%d] %v: bad state. got:\n%s\n\nwant:\n%s\n",
				i, st.command, asJSON(newState), asJSON(st.want))
		}
		if newState != nil {
			current = newState
		}
	}
}

// exactError returns an error checker that wants exactly the provided want error.
// If optName is non-empty, it's used in the error message.
func exactErr(want error, optName ...string) func(error) string {
	return func(got error) string {
		if got == want {
			return ""
		}
		if len(optName) > 0 {
			return fmt.Sprintf("got error %v, want %v", got, optName[0])
		}
		return fmt.Sprintf("got error %v, want %v", got, want)
	}
}

func cmd(s string) []string {
	return strings.Fields(s)
}
