// Command keystone is the CLI for the keystone tamper-evident log.
//
// Usage:
//
//	keystone <command> [flags]
//
// Commands:
//
//	append  add a record to the log
//	verify  check log integrity (exit 0 clean, 1 tamper, 2 operational error)
//	proof   produce an inclusion proof
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "append", "verify", "proof":
		fmt.Fprintf(os.Stderr, "keystone %s: not implemented\n", os.Args[1])
		os.Exit(2)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: keystone <append|verify|proof> [flags]")
}
