package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpHasNoFilesystemOrCredentialSideEffects(t *testing.T) {
	for _, name := range []string{"global-long", "global-short", "command", "run", "init-lab", "status"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "must-not-be-created")
			private := "SYNTHETIC_DO_NOT_ECHO_CONFIG_0123456789"
			var args []string
			switch name {
			case "global-long":
				args = []string{"--help"}
			case "global-short":
				args = []string{"-h"}
			case "command":
				args = []string{"help"}
			case "init-lab":
				args = []string{"init-lab", "--root", root, "--help"}
			default:
				args = []string{name, "--config", filepath.Join(root, private), "--help"}
			}
			original := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = w
			code := func() int { defer func() { os.Stdout = original; w.Close() }(); return run(args) }()
			raw, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			if code != 0 || strings.Contains(string(raw), private) || strings.Contains(string(raw), root) {
				t.Fatalf("unsafe help, exit=%d", code)
			}
			var value struct {
				Contract   string   `json:"contract"`
				Production bool     `json:"production_active"`
				Scope      string   `json:"scope"`
				Usage      []string `json:"usage"`
			}
			if json.Unmarshal(raw, &value) != nil || value.Contract != "cq-go-collector-help-v1" || value.Production || value.Scope != "SYNTHETIC_DISPOSABLE_ONLY" || len(value.Usage) != 5 {
				t.Fatal("help contract")
			}
			if _, err = os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("help touched configured root")
			}
		})
	}
}
