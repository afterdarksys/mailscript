package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
)

// Policy is an immutable snapshot of the root script and every loaded module.
// LoadPolicy checks syntax and name resolution without running message actions.
type Policy struct {
	source   string
	filename string
	modules  map[string]string
}

func LoadPolicy(filename string) (*Policy, error) {
	filename, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	p := &Policy{filename: filepath.Join(root, filepath.Base(filename)), modules: map[string]string{}}
	env := &scriptEnv{msg: &MessageContext{}, opts: DefaultOptions()}
	names := env.predeclared()
	visiting := map[string]bool{}
	var read func(string) (string, error)
	read = func(path string) (string, error) {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
			return "", fmt.Errorf("policy module escapes root: %s", path)
		}
		if visiting[resolved] {
			return "", fmt.Errorf("policy load cycle: %s", path)
		}
		if source, ok := p.modules[path]; ok {
			return source, nil
		}
		visiting[resolved] = true
		defer delete(visiting, resolved)
		source, err := os.ReadFile(resolved)
		if err != nil {
			return "", err
		}
		if len(source) > 4*1024*1024 || (len(p.modules) > 256 || len(visiting) > 256) {
			return "", fmt.Errorf("policy snapshot exceeds limits")
		}
		_, program, err := starlark.SourceProgram(path, source, func(name string) bool { _, ok := names[name]; return ok })
		if err != nil {
			return "", err
		}
		for i := 0; i < program.NumLoads(); i++ {
			module, _ := program.Load(i)
			if filepath.IsAbs(module) || filepath.Ext(module) != ".star" {
				return "", fmt.Errorf("load: expected relative .star path")
			}
			if _, err := read(filepath.Join(root, filepath.Clean(module))); err != nil {
				return "", err
			}
		}
		p.modules[path] = string(source)
		return string(source), nil
	}
	p.source, err = read(p.filename)
	return p, err
}

func (p *Policy) Execute(msg *MessageContext, opts Options) error {
	opts.Filename = p.filename
	opts.moduleSources = p.modules
	return ExecuteEngineWithOptions(p.source, msg, opts)
}
