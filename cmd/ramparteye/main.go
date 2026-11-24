// Command ramparteye is the RampartEye attack-surface scanner.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/scan"
	"github.com/chrobson/ramparteye/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes: 0 success, 1 failure, 2 usage, configuration or scope error.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// env is what a command runs with: a context cancelled on SIGINT/SIGTERM,
// the output streams, the process environment and test seams.
type env struct {
	ctx    context.Context
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string

	// openExchange opens the result store for import and export
	// (nil = the database named by the configuration).
	openExchange func(ctx context.Context, cfg config.Config) (web.Exchange, func(), error)
	// onListen, when set, is told the address `serve` listens on.
	onListen func(addr string)
	// nmap replaces the nmap binary in `scan` (nil = the real one).
	nmap scan.Scanner
}

// command is one subcommand; args excludes the program and command names.
type command struct {
	summary string
	run     func(e *env, args []string) int
}

// commandOrder is the order of the commands in the help text.
var commandOrder = []string{"serve", "scan", "verify", "import", "export", "migrate", "seed-demo",
	"audit", "dojo", "reset-admin", "version"}

// commands maps subcommand names to implementations.
var commands map[string]command

func init() {
	commands = map[string]command{
		"serve":       {"web UI, scan scheduler and DefectDojo auto-push", cmdServe},
		"scan":        {"scan now: --profile NAME, or the targets given (refused without scope)", cmdScan},
		"verify":      {"precision/recall of a run against a lab expectation file", cmdVerify},
		"import":      {"import nmap XML or DefectDojo Generic Findings JSON as a run", cmdImport},
		"export":      {"export a finished run to stdout: --format csv|json|dojo [--run ID]", cmdExport},
		"migrate":     {"apply database migrations", cmdMigrate},
		"seed-demo":   {"add demo targets and the scan profile \"Demo\"", cmdSeedDemo},
		"audit":       {"safety receipt of a run as JSON; non-zero exit when a check fails", cmdAudit},
		"dojo":        {"dojo push [--run ID]: push a run to DefectDojo now", cmdDojo},
		"reset-admin": {"new one-time password for a user (default admin); a login lockout clears within 15 minutes or on restart of serve", cmdResetAdmin},
		"version":     {"print the version", cmdVersion},
	}
}

func cmdVersion(e *env, _ []string) int {
	fmt.Fprintf(e.stdout, "ramparteye %s\n", version)
	return exitOK
}

// run executes a command line with the process environment.
func run(args []string, stdout, stderr io.Writer) int {
	e := &env{ctx: context.Background(), stdout: stdout, stderr: stderr, getenv: os.Getenv}
	return e.run(args)
}

func (e *env) run(args []string) int {
	if len(args) < 2 {
		usage(e.stderr)
		return exitUsage
	}
	name := args[1]
	switch name {
	case "help", "-h", "--help":
		usage(e.stdout)
		return exitOK
	}
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(e.stderr, "unknown command %q\n", name)
		usage(e.stderr)
		return exitUsage
	}
	return cmd.run(e, args[2:])
}

func usage(w io.Writer) {
	var b strings.Builder
	b.WriteString("usage: ramparteye <command> [args]\n\ncommands:\n")
	for _, n := range commandOrder {
		fmt.Fprintf(&b, "  %-12s %s\n", n, commands[n].summary)
	}
	b.WriteString("\nConfiguration comes from RAMPART_* environment variables.\n")
	_, _ = io.WriteString(w, b.String())
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		// The first signal starts a graceful stop; restoring the default
		// handling lets a second one kill the process.
		<-ctx.Done()
		stop()
	}()
	e := &env{ctx: ctx, stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv}
	code := e.run(os.Args)
	stop()
	os.Exit(code)
}
