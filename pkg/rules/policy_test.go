package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicySnapshotSurvivesModuleEdits(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "main.star")
	module := filepath.Join(root, "module.star")
	os.WriteFile(main, []byte("load(\"module.star\", \"run\")\ndef evaluate():\n    run()\n"), 0600)
	os.WriteFile(module, []byte("def run():\n    reject()\n"), 0600)
	old, err := LoadPolicy(main)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(module, []byte("def run():\n    accept()\n"), 0600)
	newer, err := LoadPolicy(main)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		policy *Policy
		want   string
	}{{old, "reject"}, {newer, "accept"}} {
		ctx := &MessageContext{}
		if err := tc.policy.Execute(ctx, DefaultOptions()); err != nil {
			t.Fatal(err)
		}
		if len(ctx.Actions) != 1 || ctx.Actions[0] != tc.want {
			t.Fatalf("got %v want %s", ctx.Actions, tc.want)
		}
	}
}

func TestPolicyRejectsInvalidReloads(t *testing.T) {
	for _, source := range []string{"def broken(:", "unknown_builtin()", "load(\"main.star\", \"x\")", "load(\"../outside.star\", \"x\")"} {
		root := t.TempDir()
		main := filepath.Join(root, "main.star")
		os.WriteFile(main, []byte(source), 0600)
		if _, err := LoadPolicy(main); err == nil {
			t.Errorf("accepted %q", source)
		}
	}
}
