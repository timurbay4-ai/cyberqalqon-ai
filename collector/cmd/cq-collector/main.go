package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"cyberqalqon.local/collector/internal/collect"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 {
		return outputError("COMMAND_REQUIRED")
	}
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		return outputHelp()
	}
	if args[0] != "init-lab" && args[0] != "init" && args[0] != "status" && args[0] != "run" && args[0] != "spool" {
		return outputError("INVALID_COMMAND")
	}
	flags := flag.NewFlagSet("cq-collector", flag.ContinueOnError)
	flags.SetOutput(discard{})
	config := flags.String("config", "", "scoped synthetic configuration")
	root := flags.String("root", "", "new empty synthetic lab directory")
	once := flags.Bool("once", false, "stop at partial line/EOF")
	steps := flags.Int("max-steps", 256, "bounded actions")
	fault := flags.String("crash-at", "", "explicit synthetic failure injection")
	parseErr := flags.Parse(args[1:])
	if parseErr == flag.ErrHelp {
		return outputHelp()
	}
	if parseErr != nil || flags.NArg() != 0 {
		return outputError("INVALID_ARGUMENTS")
	}
	if args[0] == "init-lab" {
		id, e := collect.InitLab(*root)
		if e != nil {
			return outputError(collect.Code(e))
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"contract": "cq-synthetic-lab-v1", "lab_id": id, "production_active": false})
		return 0
	}
	if *config == "" {
		return outputError("CONFIG_REQUIRED")
	}
	c, e := collect.Load(*config)
	if e != nil {
		return outputError(collect.Code(e))
	}
	allowed := map[string]bool{"": true, "AFTER_SOURCE_READ": true, "AFTER_STATE_WRITE": true, "AFTER_STATE_SYNC": true, "AFTER_STATE_COMMIT": true, "AFTER_SPOOL_COMMIT": true, "BEFORE_HTTP_SEND": true, "AFTER_HTTP_RESPONSE": true, "AFTER_ACK_VERIFIED": true, "AFTER_ACK_COMMIT": true, "AFTER_RETRY_COMMIT": true}
	if !allowed[*fault] {
		return outputError("INVALID_FAULT_POINT")
	}
	if args[0] == "status" {
		if *fault != "" {
			return outputError("STATUS_READ_ONLY")
		}
		status, err := collect.Inspect(c)
		if status.Contract != "" {
			json.NewEncoder(os.Stdout).Encode(status)
		}
		if err != nil {
			return outputError(collect.Code(err))
		}
		return 0
	}
	hook := func(stage string) {
		if *fault != "" && stage == *fault {
			os.Exit(27)
		}
	}
	x, e := collect.Open(c, args[0] == "init", hook)
	if e != nil {
		return outputError(collect.Code(e))
	}
	defer x.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "init", "status":
	case "run":
		e = x.Run(ctx, *once, *steps)
	case "spool":
		if *steps < 1 || *steps > 4096 {
			e = collect.Error("INVALID_STEP_BUDGET")
			break
		}
		for i := 0; i < *steps; i++ {
			var s string
			s, e = x.FillOne()
			if e != nil || s != "QUEUED" {
				break
			}
		}
	default:
		return outputError("INVALID_COMMAND")
	}
	json.NewEncoder(os.Stdout).Encode(x.Status())
	if e != nil {
		return outputError(collect.Code(e))
	}
	return 0
}

type discard struct{}

// Help is static and is handled before any root, source, credential or checkpoint
// access. Diagnostic output must never echo configuration values or paths.
func outputHelp() int {
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"contract": "cq-go-collector-help-v1", "scope": collect.Scope, "production_active": false,
		"usage":      []string{"cq-collector init-lab --root <new-empty-synthetic-directory>", "cq-collector init --config <synthetic-config.json>", "cq-collector status --config <synthetic-config.json>", "cq-collector spool --config <synthetic-config.json> --max-steps 8", "cq-collector run --config <synthetic-config.json> --once --max-steps 256"},
		"exit_codes": map[string]int{"success": 0, "rejected": 2, "synthetic_fault": 27},
		"notes":      []string{"Synthetic disposable roots and literal loopback endpoints only", "HTTPS verification is required unless loopback HTTP is explicitly enabled for the disposable test", "Keys are read from private files; never pass credential values on the command line", "No service installation, production enrollment, replay, reset or rebind command"},
	})
	return 0
}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
func outputError(code string) int {
	json.NewEncoder(os.Stderr).Encode(map[string]any{"error_code": code, "scope": collect.Scope, "production_active": false})
	return 2
}
