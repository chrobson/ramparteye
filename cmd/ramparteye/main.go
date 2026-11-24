// Command ramparteye is the RampartEye attack-surface scanner.
package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// command runs a subcommand; args excludes the program name and the
// subcommand name. It returns the process exit code.
type command func(args []string, stdout, stderr io.Writer) int

// commands maps subcommand names to implementations. Later tasks register
// theirs here.
var commands = map[string]command{
	"version": func(_ []string, stdout, _ io.Writer) int {
		fmt.Fprintf(stdout, "ramparteye %s\n", version)
		return 0
	},
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		usage(stderr)
		return 2
	}
	name := args[1]
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n", name)
		usage(stderr)
		return 2
	}
	return cmd(args[2:], stdout, stderr)
}

func usage(w io.Writer) {
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(w, "usage: ramparteye <command> [args]\ncommands: %s\n", strings.Join(names, ", "))
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}
