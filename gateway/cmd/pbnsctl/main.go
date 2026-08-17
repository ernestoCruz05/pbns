package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"pbns.local/gateway/internal/store"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if stdout == nil || stderr == nil {
		return 2
	}
	flags := flag.NewFlagSet("pbnsctl", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var databasePath string
	flags.StringVar(&databasePath, "db", "", "private PBNS gateway database")
	if err := flags.Parse(arguments); err != nil || flags.NArg() == 0 {
		writeError(stderr, "usage: pbnsctl [--db FILE] enrollment|hosts|baseline|keys|recovery ...")
		return 2
	}
	if flags.Arg(0) == "keys" || flags.Arg(0) == "recovery" {
		var err error
		if flags.Arg(0) == "keys" {
			err = runKeys(flags.Args()[1:], stdout)
		} else {
			err = runRecovery(flags.Args()[1:], stdout)
		}
		if err != nil {
			writeError(stderr, err.Error())
			return 1
		}
		return 0
	}
	if databasePath == "" {
		writeError(stderr, "--db is required for enrollment, hosts, and baseline")
		return 2
	}
	database, err := store.Open(databasePath, store.DefaultOptions())
	if err != nil {
		writeError(stderr, err.Error())
		return 1
	}
	status := 0
	switch flags.Arg(0) {
	case "enrollment":
		err = runEnrollment(database, flags.Args()[1:], stdout)
	case "hosts":
		err = runHosts(database, flags.Args()[1:], stdout)
	case "baseline":
		err = runBaseline(database, flags.Args()[1:], stdout)
	default:
		err = fmt.Errorf("unknown command")
	}
	if err != nil {
		writeError(stderr, err.Error())
		status = 1
	}
	if closeErr := database.Close(); closeErr != nil {
		writeError(stderr, "database close failed")
		status = 1
	}
	return status
}

func writeError(writer io.Writer, message string) {
	_, _ = fmt.Fprintf(writer, "pbnsctl: %s\n", message)
}
