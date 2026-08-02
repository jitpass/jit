// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Command kubectl-fifo-manifest-spike answers the open empirical questions in
// the k8s Secret-manifest migration plan:
//
//  1. Does `kubectl apply -f <path>` read a named pipe (FIFO), and how many
//     times does one invocation open it? (-mode fifo)
//  2. Does a jit decoy manifest (data: values like "jit-hidden-X", which are
//     not valid base64) fail loudly under a real `kubectl apply`, and does a
//     stringData decoy slip through silently? (-mode apiserver)
//
// -mode fifo mimics internal/mount.Serve faithfully in miniature: mkfifo,
// then loop { open O_WRONLY (blocks for a reader) -> write -> close ->
// RECREATE the FIFO by mkfifo-at-sibling + rename-over }. The recreate step
// matters: without it, a reader that still holds the old read end open makes
// the server's next open() succeed instantly and the same reader receives the
// payload again, concatenated — the first version of this spike counted 16
// phantom "opens" for one kubectl run exactly because it skipped this.
//
// -mode apiserver is the smallest HTTP server that lets kubectl run a REAL
// (not --dry-run) apply with no cluster: core-v1 discovery plus a secrets
// endpoint whose POST/PUT handler decodes the object into a struct with
// `Data map[string][]byte` — the same json-[]byte typed decode the actual
// kube-apiserver performs, which is where "illegal base64 data" originates.
// It is a fake in every other respect; the decode semantics are the part
// under test.
//
// Deliberately dependency-free (stdlib only), like the spike convention.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	mode := flag.String("mode", "", "fifo | apiserver")
	path := flag.String("path", "", "fifo mode: where to create and serve the FIFO")
	file := flag.String("file", "", "fifo mode: manifest file whose bytes each reader receives")
	maxCycles := flag.Int("max-cycles", 8, "fifo mode: stop after this many serve cycles")
	idleExit := flag.Duration("idle-exit", 8*time.Second, "fifo mode: exit after this long with no new reader")
	listen := flag.String("listen", "127.0.0.1:18080", "apiserver mode: listen address")
	flag.Parse()

	switch *mode {
	case "fifo":
		if *path == "" || *file == "" {
			fmt.Fprintln(os.Stderr, "usage: -mode fifo -path <fifo> -file <manifest>")
			os.Exit(2)
		}
		serveFIFO(*path, *file, *maxCycles, *idleExit)
	case "apiserver":
		serveMockAPI(*listen)
	default:
		fmt.Fprintln(os.Stderr, "usage: -mode fifo|apiserver")
		os.Exit(2)
	}
}

// --- fifo mode -------------------------------------------------------------

func serveFIFO(path, file string, maxCycles int, idleExit time.Duration) {
	content, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read manifest:", err)
		os.Exit(1)
	}
	_ = os.Remove(path)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "mkfifo:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "SERVER ready fifo=%s bytes=%d\n", path, len(content))

	// open(2) O_WRONLY on a FIFO blocks forever with no reader, so the
	// idle watchdog has to live off the main loop.
	served := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-served:
			case <-time.After(idleExit):
				fmt.Fprintln(os.Stderr, "SERVER idle-exit")
				os.Exit(0)
			}
		}
	}()

	start := time.Now()
	for cycle := 1; cycle <= maxCycles; cycle++ {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open:", err)
			os.Exit(1)
		}
		n, werr := f.Write(content)
		cerr := f.Close()
		fmt.Fprintf(os.Stderr, "SERVER cycle=%d t=%dms wrote=%d writeErr=%v closeErr=%v\n",
			cycle, time.Since(start).Milliseconds(), n, werr, cerr)

		// Isolate any reader still holding the old read end, exactly like
		// internal/mount's recreateFIFO: fresh FIFO at a sibling path,
		// atomically renamed over the served path.
		sibling := filepath.Join(filepath.Dir(path), ".spike-next.fifo")
		_ = os.Remove(sibling)
		if err := syscall.Mkfifo(sibling, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "mkfifo sibling:", err)
			os.Exit(1)
		}
		if err := os.Rename(sibling, path); err != nil {
			fmt.Fprintln(os.Stderr, "rename:", err)
			os.Exit(1)
		}
		select {
		case served <- struct{}{}:
		default:
		}
	}
	fmt.Fprintln(os.Stderr, "SERVER max-cycles reached")
}

// --- apiserver mode --------------------------------------------------------

// mockSecret is the decode seam under test: `Data map[string][]byte` makes
// encoding/json base64-decode every data value during Unmarshal, which is
// byte-for-byte the mechanism (json []byte fields) behind the real
// apiserver's "illegal base64 data at input byte N" rejection.
type mockSecret struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   map[string]any    `json:"metadata"`
	Type       string            `json:"type,omitempty"`
	Data       map[string][]byte `json:"data,omitempty"`
	StringData map[string]string `json:"stringData,omitempty"`
}

func serveMockAPI(listen string) {
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "API "+format+"\n", a...) }
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	status := func(w http.ResponseWriter, code int, reason, msg string) {
		writeJSON(w, code, map[string]any{
			"kind": "Status", "apiVersion": "v1", "status": "Failure",
			"message": msg, "reason": reason, "code": code,
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"kind": "APIVersions", "versions": []string{"v1"}})
	})
	mux.HandleFunc("/apis", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": []any{}})
	})
	mux.HandleFunc("/api/v1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"kind": "APIResourceList", "groupVersion": "v1",
			"resources": []map[string]any{{
				"name": "secrets", "singularName": "secret", "namespaced": true,
				"kind": "Secret", "verbs": []string{"create", "get", "update", "patch", "delete", "list"},
			}},
		})
	})
	mux.HandleFunc("/api/v1/namespaces/default/secrets/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/default/secrets/")
		logf("%s %s", r.Method, r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			// Always "not found" so apply takes the create path.
			status(w, 404, "NotFound", fmt.Sprintf("secrets %q not found", name))
		case http.MethodPut, http.MethodPatch:
			handleSecretWrite(w, r, logf, writeJSON, status)
		default:
			status(w, 405, "MethodNotAllowed", r.Method)
		}
	})
	mux.HandleFunc("/api/v1/namespaces/default/secrets", func(w http.ResponseWriter, r *http.Request) {
		logf("%s %s", r.Method, r.URL.Path)
		if r.Method != http.MethodPost {
			status(w, 405, "MethodNotAllowed", r.Method)
			return
		}
		handleSecretWrite(w, r, logf, writeJSON, status)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logf("(unhandled) %s %s -> 404", r.Method, r.URL.Path)
		status(w, 404, "NotFound", "the server could not find the requested resource")
	})

	logf("listening on %s", listen)
	if err := http.ListenAndServe(listen, mux); err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
}

func handleSecretWrite(w http.ResponseWriter, r *http.Request,
	logf func(string, ...any), writeJSON func(http.ResponseWriter, int, any),
	status func(http.ResponseWriter, int, string, string)) {

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		status(w, 400, "BadRequest", err.Error())
		return
	}
	var s mockSecret
	if err := json.Unmarshal(body, &s); err != nil {
		// The real apiserver's wording for this exact failure.
		msg := fmt.Sprintf("Secret in version \"v1\" cannot be handled as a Secret: %v", err)
		logf("REJECTED: %s", msg)
		status(w, 400, "BadRequest", msg)
		return
	}
	// Mirror the real server: fold stringData into data (stringData wins).
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	for k, v := range s.StringData {
		s.Data[k] = []byte(v)
	}
	s.StringData = nil
	for k, v := range s.Data {
		logf("ACCEPTED key=%s storedValue=%q", k, string(v))
	}
	writeJSON(w, 201, s)
}
