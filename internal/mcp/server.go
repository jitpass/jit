// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/job"
	"github.com/jitpass/jit/internal/profile"
)

// Backend is what the server needs from the jit service: the two job RPCs
// a socket client can make. The CLI wires an agent.Client; tests wire a fake.
type Backend interface {
	ListJobs() ([]agent.JobStatus, error)
	RunJob(name string) (agent.JobResult, error)
	// RequestJob hands a proposal to JitPass to show the human. An error
	// carrying agent.ErrNoJobBroker's text means no app is running.
	RequestJob(name string, spec agent.JobSpec, why string) error
}

// Server answers MCP over one stdin/stdout pair.
type Server struct {
	Backend Backend
	// Version is jit's own, reported as serverInfo.version.
	Version string

	wmu sync.Mutex
	out io.Writer
}

// protocolVersions are the MCP revisions this server speaks, newest first.
// A client asking for one of them gets it back; any other gets the newest,
// which the spec says the client then accepts or disconnects over.
var protocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// maxLine bounds one incoming message. Every request this server takes is a
// few hundred bytes; the bound keeps a runaway client from growing the
// buffer without limit.
const maxLine = 1 << 20

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC error codes the server uses.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// Serve reads one message per line from in until it closes, answering on
// out. Requests are handled concurrently, because a run_job can take minutes
// and a ping must not wait behind it; writes are serialized so two answers
// never interleave on the line.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	s.out = out
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	var wg sync.WaitGroup
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		msg := append([]byte(nil), line...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleLine(msg)
		}()
	}
	wg.Wait()
	return sc.Err()
}

func (s *Server) handleLine(line []byte) {
	if line[0] == '[' {
		// A batch (MCP 2025-03-26). Answered as an array, in order.
		var batch []json.RawMessage
		if err := json.Unmarshal(line, &batch); err != nil || len(batch) == 0 {
			s.write(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{codeParse, "invalid batch"}})
			return
		}
		var out []response
		for _, m := range batch {
			if r, ok := s.handle(m); ok {
				out = append(out, r)
			}
		}
		if len(out) > 0 {
			s.write(out)
		}
		return
	}
	if r, ok := s.handle(line); ok {
		s.write(r)
	}
}

// handle answers one message. ok is false for a notification, which gets no
// answer.
func (s *Server) handle(raw []byte) (response, bool) {
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{codeParse, "not JSON"}}, true
	}
	if len(req.ID) == 0 {
		return response{}, false // notifications/initialized and the like
	}
	resp := response{JSONRPC: "2.0", ID: req.ID}
	if req.JSONRPC != "2.0" || req.Method == "" {
		resp.Error = &rpcError{codeInvalidRequest, "not a JSON-RPC 2.0 request"}
		return resp, true
	}
	switch req.Method {
	case "initialize":
		resp.Result = s.initialize(req.Params)
	case "ping":
		resp.Result = struct{}{}
	case "tools/list":
		resp.Result = map[string]any{"tools": tools()}
	case "tools/call":
		result, err := s.call(req.Params)
		if err != nil {
			resp.Error = err
		} else {
			resp.Result = result
		}
	default:
		resp.Error = &rpcError{codeMethodNotFound, "method not found: " + req.Method}
	}
	return resp, true
}

func (s *Server) write(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, _ = s.out.Write(append(data, '\n'))
}

// instructions is what the model reads about this server, once, at
// initialize. It says what the tools do and the one thing it can never get.
const instructions = `Run the user's approved AI jobs on their Mac. An AI job is a command the user approved, with the secrets it needs. Call list_jobs to see them and run_job to run one. The jit service runs the command and returns its output with every secret value replaced by [hidden: NAME]: you never see a key, and you cannot. A job whose files changed since approval will not run until the user approves it again. If the job you need does not exist, call request_job to propose it; only the user can approve it.`

func (s *Server) initialize(params json.RawMessage) any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	version := protocolVersions[0]
	for _, v := range protocolVersions {
		if v == p.ProtocolVersion {
			version = v
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": "jit", "title": "jit AI jobs", "version": s.Version},
		"instructions":    instructions,
	}
}

type tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func tools() []tool {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	return []tool{
		{
			Name:        "list_jobs",
			Title:       "List AI jobs",
			Description: "List the AI jobs the user approved on this Mac: what each runs, where, whether it can run now, and whether it asks the user before running. Never returns secret values.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
			Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		},
		{
			Name:  "run_job",
			Title: "Run an AI job",
			Description: "Run one approved AI job by name. The jit service runs it on the user's Mac with its secrets and returns the exit code and output, " +
				"with every secret value replaced by [hidden: NAME]. A job set to ask each time shows the user a Touch ID prompt first. Files the job wrote are listed by path.",
			InputSchema: map[string]any{
				"type":                 "object",
				"properties":           map[string]any{"name": str("the job's name, as list_jobs shows it")},
				"required":             []string{"name"},
				"additionalProperties": false,
			},
			Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "openWorldHint": true},
		},
		{
			Name:  "request_job",
			Title: "Propose an AI job",
			Description: "Propose a new AI job for the user to approve. Creates nothing: it returns the exact command the user runs on their Mac to see the whole job and approve it with Touch ID. " +
				"The command must be a script file, not an inline program (no python -c, sh -c, node -e) and not a command that prints its input (env, cat, echo).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":    str("a short name: lowercase letters, digits and dashes, e.g. notion-export"),
					"folder":  str("absolute path of the folder the command runs in; its profile and script live there"),
					"command": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "the command and its arguments, e.g. [\".venv/bin/python\", \"export_pages.py\"]"},
					"profile": str("the jit profile whose secrets the job needs; optional when the folder has only one"),
					"why":     str("one sentence for the user: what the job is for"),
				},
				"required":             []string{"name", "folder", "command"},
				"additionalProperties": false,
			},
			Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		},
	}
}

type callResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(text string, isError bool) callResult {
	return callResult{Content: []content{{Type: "text", Text: text}}, IsError: isError}
}

func (s *Server) call(params json.RawMessage) (callResult, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return callResult{}, &rpcError{codeInvalidParams, "tools/call: bad params"}
	}
	switch p.Name {
	case "list_jobs":
		return s.listJobs(), nil
	case "run_job":
		var a struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(p.Arguments, &a); err != nil || a.Name == "" {
			return callResult{}, &rpcError{codeInvalidParams, "run_job: give the job's name"}
		}
		return s.runJob(a.Name), nil
	case "request_job":
		var a jobProposal
		if err := json.Unmarshal(p.Arguments, &a); err != nil {
			return callResult{}, &rpcError{codeInvalidParams, "request_job: bad arguments"}
		}
		return s.requestJob(a), nil
	}
	return callResult{}, &rpcError{codeInvalidParams, "unknown tool: " + p.Name}
}

// serviceError turns a service refusal into the sentence the model should
// relay, without the RPC framing ("agent: job_run: ...").
func serviceError(err error) string {
	msg := err.Error()
	for _, prefix := range []string{"agent: ", "job_run: ", "job_list: "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return msg
}

func (s *Server) listJobs() callResult {
	jobs, err := s.Backend.ListJobs()
	if err != nil {
		return textResult("The jit service could not list jobs: "+serviceError(err), true)
	}
	if len(jobs) == 0 {
		return textResult("No AI jobs are approved on this Mac yet. To propose one, call request_job; only the user can approve it.", false)
	}
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].Name < jobs[b].Name })
	var b strings.Builder
	fmt.Fprintf(&b, "%d AI job(s). Run one with run_job.\n", len(jobs))
	for _, j := range jobs {
		fmt.Fprintf(&b, "\n%s: %s\n", j.Name, jobStateLine(j))
		if j.Description != "" {
			fmt.Fprintf(&b, "  %s\n", j.Description)
		}
		fmt.Fprintf(&b, "  runs: %s\n  in: %s\n", strings.Join(j.Argv, " "), j.Dir)
	}
	return textResult(b.String(), false)
}

func jobStateLine(j agent.JobStatus) string {
	switch j.State {
	case agent.JobChanged:
		switch {
		case len(j.Changes) > 0:
			return fmt.Sprintf("cannot run: %s %s since the user approved it. The user must approve it again.", j.Changes[0].Path, j.Changes[0].Kind)
		case j.LastRefusal != "":
			return "cannot run: stopped because " + j.LastRefusal + ". The user must approve it again."
		}
		return "cannot run: its files changed since the user approved it. The user must approve it again."
	case agent.JobRotated:
		return "cannot run: a secret was rotated since the user approved it. The user must approve it again."
	}
	if j.Ask == string(job.AskNever) {
		return "ready, runs without asking the user"
	}
	return "ready, asks the user (Touch ID) each time"
}

func (s *Server) runJob(name string) callResult {
	if err := job.ValidateName(name); err != nil {
		return textResult(err.Error(), true)
	}
	res, err := s.Backend.RunJob(name)
	if err != nil {
		return textResult("The job did not run: "+serviceError(err), true)
	}
	var b strings.Builder
	switch {
	case res.TimedOut:
		fmt.Fprintf(&b, "%s was stopped at the time limit after %.1f s.\n", name, float64(res.DurationMS)/1000)
	default:
		fmt.Fprintf(&b, "%s exited %d after %.1f s.\n", name, res.Exit, float64(res.DurationMS)/1000)
	}
	fmt.Fprintf(&b, "\n--- stdout ---\n%s", res.Stdout)
	if !strings.HasSuffix(res.Stdout, "\n") && res.Stdout != "" {
		b.WriteString("\n")
	}
	if res.Stderr != "" {
		fmt.Fprintf(&b, "--- stderr ---\n%s", res.Stderr)
		if !strings.HasSuffix(res.Stderr, "\n") {
			b.WriteString("\n")
		}
	}
	b.WriteString("---\n")
	for _, f := range res.NewFiles {
		fmt.Fprintf(&b, "[jit] new file: %s\n", f)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(&b, "[jit] %s\n", n)
	}
	fmt.Fprintf(&b, "[jit] %s\n", hiddenLine(res.Hidden))
	return textResult(b.String(), res.Exit != 0 || res.TimedOut)
}

func hiddenLine(hidden map[string]int) string {
	if len(hidden) == 0 {
		return "hidden values: none"
	}
	names := make([]string, 0, len(hidden))
	for k := range hidden {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, k := range names {
		parts = append(parts, fmt.Sprintf("%s x%d", k, hidden[k]))
	}
	return "hidden values: " + strings.Join(parts, ", ")
}

type jobProposal struct {
	Name    string   `json:"name"`
	Folder  string   `json:"folder"`
	Command []string `json:"command"`
	Profile string   `json:"profile"`
	Why     string   `json:"why"`
}

// requestJob hands a proposal to the human. With JitPass running it goes to
// the app, which shows it pre-filled for the human to read and approve with
// Touch ID; without it, the answer is the `jit job allow` line for the human
// to run. It creates nothing either way. The proposal is checked here too so
// the model hears a refusal now rather than the human hearing it later.
func (s *Server) requestJob(p jobProposal) callResult {
	if err := job.ValidateName(p.Name); err != nil {
		return textResult(err.Error(), true)
	}
	if !filepath.IsAbs(p.Folder) {
		return textResult("folder must be an absolute path", true)
	}
	if err := job.CheckArgv(p.Command); err != nil {
		return textResult("jit would refuse this job: "+err.Error(), true)
	}
	if p.Profile != "" && strings.ContainsAny(p.Profile, "/\\ \t\n") {
		return textResult("profile must be a profile name, not a path", true)
	}
	// The folder's only profile when none is named, as `jit job allow`
	// picks it: a proposal that left it out became, in the live test, a
	// sheet whose approval would have made a job with no secrets.
	if p.Profile == "" {
		matches, _ := filepath.Glob(filepath.Join(p.Folder, profile.ProfilesDir, "*.yaml"))
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, strings.TrimSuffix(filepath.Base(m), ".yaml"))
		}
		sort.Strings(names)
		switch len(names) {
		case 1:
			p.Profile = names[0]
		case 0:
		default:
			return textResult(fmt.Sprintf("this folder has %d profiles (%s): name the one the job needs in profile", len(names), strings.Join(names, ", ")), true)
		}
	}
	var prof *agent.GrantProfile
	if p.Profile != "" {
		prof = &agent.GrantProfile{Name: p.Profile, Root: p.Folder}
	}
	err := s.Backend.RequestJob(p.Name, agent.JobSpec{Dir: p.Folder, Argv: p.Command, Profile: prof}, p.Why)
	if err == nil {
		return textResult("Sent to JitPass on the user's Mac. Nothing was created: the user reads the whole job there and approves it with Touch ID, or dismisses it. "+
			"Once approved, call run_job with the name "+p.Name+". You will see the job's output, never its secret values.", false)
	}
	if !strings.Contains(err.Error(), agent.ErrNoJobBroker.Error()) {
		return textResult("The proposal was not accepted: "+serviceError(err), true)
	}
	parts := []string{"cd", quote(p.Folder), "&&", "jit", "job", "allow", p.Name}
	if p.Profile != "" {
		parts = append(parts, "--profile", quote(p.Profile))
	}
	parts = append(parts, "--")
	for _, a := range p.Command {
		parts = append(parts, quote(a))
	}
	return textResult("Nothing was created: only the user can approve an AI job. Ask them to run this in a terminal on their Mac:\n\n    "+
		strings.Join(parts, " ")+
		"\n\nIt shows them the whole job, then asks for Touch ID. Once approved, call run_job with the name "+p.Name+
		". You will see the job's output, never its secret values.", false)
}

// quote leaves a plain word bare and single-quotes anything else, so the line
// the model relays pastes into a shell as exactly the argv it proposed and
// nothing more: a proposal cannot smuggle a second command through `;` or
// `$(...)`.
func quote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./=:@%+,", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
