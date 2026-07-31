package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/mailscript/pkg/ml"
	"go.starlark.net/starlark"
)

// Options controls how a rule script is executed.
type Options struct {
	// MaxSteps bounds Starlark execution. A rule that loops forever would
	// otherwise wedge an SMTP worker; the limit turns that into a per-message
	// error. Zero applies DefaultMaxSteps.
	MaxSteps uint64

	// Timeout bounds wall-clock execution, covering the DNS lookups that step
	// counting cannot see. Zero applies DefaultTimeout.
	Timeout time.Duration

	// Models supplies the classifiers available to ML builtins.
	Models *ml.Registry

	// BertTokenizer supplies the WordPiece vocabulary for bert_tokens.
	BertTokenizer *ml.BertTokenizer

	// Filename is the name reported in Starlark tracebacks.
	Filename string

	// Print receives output from the Starlark print() builtin. When nil,
	// print() writes to the message's log entries.
	Print func(msg string)
}

// Execution limits applied when Options leaves them unset.
const (
	DefaultMaxSteps = 10_000_000
	DefaultTimeout  = 5 * time.Second
)

// DefaultOptions returns the options used by ExecuteEngine.
func DefaultOptions() Options {
	return Options{
		MaxSteps: DefaultMaxSteps,
		Timeout:  DefaultTimeout,
		Filename: "script.star",
	}
}

// ExecuteEngine runs a Starlark source script against the message context
// using default execution limits.
func ExecuteEngine(scriptSource string, msg *MessageContext) error {
	return ExecuteEngineWithOptions(scriptSource, msg, DefaultOptions())
}

// ExecuteEngineWithOptions runs a script with explicit limits and resources.
func ExecuteEngineWithOptions(scriptSource string, msg *MessageContext, opts Options) error {
	if msg == nil {
		return fmt.Errorf("mailscript: nil message context")
	}
	normalizeContext(msg)

	if opts.MaxSteps == 0 {
		opts.MaxSteps = DefaultMaxSteps
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Filename == "" {
		opts.Filename = "script.star"
	}

	env := &scriptEnv{msg: msg, opts: opts}
	predeclared := env.predeclared()

	thread := &starlark.Thread{
		Name: "MailScriptEngine",
		Print: func(_ *starlark.Thread, text string) {
			if opts.Print != nil {
				opts.Print(text)
				return
			}
			msg.LogEntries = append(msg.LogEntries, text)
		},
	}
	thread.SetMaxExecutionSteps(opts.MaxSteps)

	// Cancel on timeout so that a script blocked in a slow DNS lookup, which
	// consumes no execution steps, still terminates.
	done := make(chan struct{})
	defer close(done)
	go func() {
		timer := time.NewTimer(opts.Timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			thread.Cancel(fmt.Sprintf("exceeded %s time limit", opts.Timeout))
		case <-done:
		}
	}()

	globals, err := starlark.ExecFile(thread, opts.Filename, scriptSource, predeclared)
	if err != nil {
		return fmt.Errorf("starlark execution failed: %w", wrapEvalError(err))
	}

	// A script may define evaluate() as its entry point, or do its work at
	// module level. Both forms are supported.
	evalFunc, ok := globals["evaluate"]
	if !ok {
		if len(msg.Actions) == 0 {
			msg.Actions = append(msg.Actions, "accept")
		}
		return nil
	}

	callable, ok := evalFunc.(starlark.Callable)
	if !ok {
		return fmt.Errorf("starlark execution failed: 'evaluate' is %s, not a function", evalFunc.Type())
	}

	if _, err := starlark.Call(thread, callable, nil, nil); err != nil {
		return fmt.Errorf("failed calling evaluate(): %w", wrapEvalError(err))
	}
	return nil
}

// wrapEvalError attaches the Starlark backtrace, which names the failing line
// and is the only useful part of a rule failure in production logs.
func wrapEvalError(err error) error {
	if evalErr, ok := err.(*starlark.EvalError); ok {
		return fmt.Errorf("%s\n%s", evalErr.Msg, evalErr.Backtrace())
	}
	return err
}

// normalizeContext fills in the derived state that callers constructing a
// MessageContext by hand are not expected to populate.
func normalizeContext(m *MessageContext) {
	if m.Headers == nil {
		m.Headers = make(map[string]string)
	}
	if m.ModifiedHeaders == nil {
		m.ModifiedHeaders = make(map[string]string)
	}
	if m.Actions == nil {
		m.Actions = []string{}
	}
	if m.LogEntries == nil {
		m.LogEntries = []string{}
	}
	if m.ScoreReasons == nil {
		m.ScoreReasons = []string{}
	}

	// A context built from the Headers map alone has no header list; derive
	// one so the duplicate-aware and case-insensitive accessors work.
	if len(m.HeaderList) == 0 && len(m.Headers) > 0 {
		names := make([]string, 0, len(m.Headers))
		for name := range m.Headers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			m.HeaderList = append(m.HeaderList, Header{
				Name:  name,
				Value: m.Headers[name],
				Raw:   name + ": " + m.Headers[name],
			})
		}
	}
	if m.headerIndex == nil {
		m.reindex()
	}

	// Derive the decoded bodies when the caller supplied only a raw body.
	if m.TextBody == "" && m.HTMLBody == "" && m.Body != "" && len(m.Parts) == 0 {
		m.decodeMIME()
	}
	if m.BodySize == 0 {
		m.BodySize = int64(len(m.Body))
	}
	if m.SenderDomain == "" {
		m.SenderDomain = DomainOf(m.Get("From"))
	}
}

// scriptEnv carries the state the builtins close over.
type scriptEnv struct {
	msg  *MessageContext
	opts Options
}

// predeclared assembles the full MailScript standard library.
func (e *scriptEnv) predeclared() starlark.StringDict {
	dict := starlark.StringDict{}
	for _, group := range []func() starlark.StringDict{
		e.actionBuiltins,
		e.headerBuiltins,
		e.matchBuiltins,
		e.metadataBuiltins,
		e.validationBuiltins,
		e.identityBuiltins,
		e.authBuiltins,
		e.verifyBuiltins,
		e.receivedBuiltins,
		e.contentBuiltins,
		e.attachmentBuiltins,
		e.humanBuiltins,
		e.scoreBuiltins,
		e.networkBuiltins,
		e.listBuiltins,
		e.mlBuiltins,
		e.legacyBuiltins,
	} {
		for name, value := range group() {
			dict[name] = value
		}
	}
	return dict
}

// ---------------------------------------------------------------------------
// Builtin construction helpers
//
// Each helper wraps the argument unpacking and type conversion that would
// otherwise be repeated for every one of the ~160 builtins.
// ---------------------------------------------------------------------------

func nullary(name string, fn func() starlark.Value) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		return fn(), nil
	})
}

func nullaryStr(name string, fn func() string) *starlark.Builtin {
	return nullary(name, func() starlark.Value { return starlark.String(fn()) })
}

func nullaryBool(name string, fn func() bool) *starlark.Builtin {
	return nullary(name, func() starlark.Value { return starlark.Bool(fn()) })
}

func nullaryInt(name string, fn func() int) *starlark.Builtin {
	return nullary(name, func() starlark.Value { return starlark.MakeInt(fn()) })
}

func nullaryFloat(name string, fn func() float64) *starlark.Builtin {
	return nullary(name, func() starlark.Value { return starlark.Float(fn()) })
}

func nullaryList(name string, fn func() []string) *starlark.Builtin {
	return nullary(name, func() starlark.Value { return stringList(fn()) })
}

// unary builds a builtin taking one required string argument.
func unary(name, arg string, fn func(string) starlark.Value) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var v string
		if err := starlark.UnpackArgs(name, args, kwargs, arg, &v); err != nil {
			return nil, err
		}
		return fn(v), nil
	})
}

func unaryStr(name, arg string, fn func(string) string) *starlark.Builtin {
	return unary(name, arg, func(v string) starlark.Value { return starlark.String(fn(v)) })
}

func unaryBool(name, arg string, fn func(string) bool) *starlark.Builtin {
	return unary(name, arg, func(v string) starlark.Value { return starlark.Bool(fn(v)) })
}

func unaryInt(name, arg string, fn func(string) int) *starlark.Builtin {
	return unary(name, arg, func(v string) starlark.Value { return starlark.MakeInt(fn(v)) })
}

func unaryFloat(name, arg string, fn func(string) float64) *starlark.Builtin {
	return unary(name, arg, func(v string) starlark.Value { return starlark.Float(fn(v)) })
}

func unaryList(name, arg string, fn func(string) []string) *starlark.Builtin {
	return unary(name, arg, func(v string) starlark.Value { return stringList(fn(v)) })
}

// binary builds a builtin taking two required string arguments.
func binary(name, arg1, arg2 string, fn func(string, string) (starlark.Value, error)) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var a, c string
		if err := starlark.UnpackArgs(name, args, kwargs, arg1, &a, arg2, &c); err != nil {
			return nil, err
		}
		return fn(a, c)
	})
}

// action builds a builtin that records a no-argument action.
func (e *scriptEnv) action(name string) *starlark.Builtin {
	return nullary(name, func() starlark.Value {
		e.msg.Actions = append(e.msg.Actions, name)
		return starlark.None
	})
}

// actionArg builds a builtin that records an action with one string operand.
func (e *scriptEnv) actionArg(name, arg string) *starlark.Builtin {
	return unary(name, arg, func(v string) starlark.Value {
		e.msg.Actions = append(e.msg.Actions, fmt.Sprintf("%s:%s", name, v))
		return starlark.None
	})
}

// ---------------------------------------------------------------------------
// Value conversion
// ---------------------------------------------------------------------------

func stringList(items []string) *starlark.List {
	values := make([]starlark.Value, len(items))
	for i, s := range items {
		values[i] = starlark.String(s)
	}
	return starlark.NewList(values)
}

func stringDict(m map[string]string) *starlark.Dict {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	dict := starlark.NewDict(len(m))
	for _, k := range keys {
		_ = dict.SetKey(starlark.String(k), starlark.String(m[k]))
	}
	return dict
}

func floatDict(m map[string]float64) *starlark.Dict {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	dict := starlark.NewDict(len(m))
	for _, k := range keys {
		_ = dict.SetKey(starlark.String(k), starlark.Float(m[k]))
	}
	return dict
}

// dictOf builds a Starlark dict from alternating key and value arguments,
// which keeps the many small record-shaped returns readable.
func dictOf(pairs ...interface{}) *starlark.Dict {
	dict := starlark.NewDict(len(pairs) / 2)
	for i := 0; i+1 < len(pairs); i += 2 {
		key, ok := pairs[i].(string)
		if !ok {
			continue
		}
		_ = dict.SetKey(starlark.String(key), toStarlark(pairs[i+1]))
	}
	return dict
}

// toStarlark converts the Go types the builtins produce into Starlark values.
func toStarlark(v interface{}) starlark.Value {
	switch value := v.(type) {
	case nil:
		return starlark.None
	case starlark.Value:
		return value
	case string:
		return starlark.String(value)
	case bool:
		return starlark.Bool(value)
	case int:
		return starlark.MakeInt(value)
	case int64:
		return starlark.MakeInt64(value)
	case float64:
		return starlark.Float(value)
	case []string:
		return stringList(value)
	case map[string]string:
		return stringDict(value)
	case map[string]float64:
		return floatDict(value)
	case time.Time:
		if value.IsZero() {
			return starlark.None
		}
		return starlark.String(value.Format(time.RFC3339))
	default:
		return starlark.String(fmt.Sprint(value))
	}
}

// stringsFromValue accepts either a single string or an iterable of strings,
// so that rules can pass one extension or a list of them interchangeably.
func stringsFromValue(v starlark.Value) ([]string, error) {
	if v == nil || v == starlark.None {
		return nil, nil
	}
	if s, ok := starlark.AsString(v); ok {
		return []string{s}, nil
	}

	iterable, ok := v.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("expected a string or a list of strings, got %s", v.Type())
	}

	iter := iterable.Iterate()
	defer iter.Done()

	var out []string
	var item starlark.Value
	for iter.Next(&item) {
		s, ok := starlark.AsString(item)
		if !ok {
			return nil, fmt.Errorf("expected string elements, got %s", item.Type())
		}
		out = append(out, s)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

func (e *scriptEnv) actionBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"accept":     e.action("accept"),
		"discard":    e.action("discard"),
		"drop":       e.action("drop"),
		"bounce":     e.action("bounce"),
		"quarantine": e.action("quarantine"),
		"reject":     e.action("reject"),
		"defer":      e.action("defer"),

		"fileinto":   e.actionArg("fileinto", "folder"),
		"divert_to":  e.actionArg("divert_to", "email_address"),
		"screen_to":  e.actionArg("screen_to", "email_address"),
		"redirect":   e.actionArg("redirect", "email_address"),
		"tag":        e.actionArg("tag", "label"),
		"auto_reply": e.actionArg("auto_reply", "text"),

		"add_to_next_digest": nullary("add_to_next_digest", func() starlark.Value {
			msg.Actions = append(msg.Actions, "add_to_digest")
			return starlark.Bool(true)
		}),

		"log_entry": unary("log_entry", "message", func(text string) starlark.Value {
			msg.LogEntries = append(msg.LogEntries, text)
			msg.Actions = append(msg.Actions, "log:"+text)
			return starlark.None
		}),

		"reply_with_smtp_error": starlark.NewBuiltin("reply_with_smtp_error",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var code int
				var text string
				if err := starlark.UnpackArgs("reply_with_smtp_error", args, kwargs, "code", &code, "text?", &text); err != nil {
					return nil, err
				}
				if code < 400 || code > 599 {
					return nil, fmt.Errorf("reply_with_smtp_error: code %d is not a 4xx or 5xx SMTP status", code)
				}
				if text != "" {
					msg.Actions = append(msg.Actions, fmt.Sprintf("smtp_error:%d:%s", code, text))
				} else {
					msg.Actions = append(msg.Actions, fmt.Sprintf("smtp_error:%d", code))
				}
				return starlark.None, nil
			}),

		"reply_with_smtp_dsn": e.actionArg("reply_with_smtp_dsn", "dsn"),

		"set_dlp":  e.actionPair("set_dlp", "mode", "target"),
		"skip_dlp": e.actionPair("skip_dlp", "mode", "target"),

		"skip_malware_check":   e.actionArg("skip_malware_check", "sender"),
		"skip_spam_check":      e.actionArg("skip_spam_check", "sender"),
		"skip_whitelist_check": e.actionArg("skip_whitelist_check", "ip"),
		"force_second_pass":    e.actionArg("force_second_pass", "mailserver"),

		"get_actions": nullaryList("get_actions", func() []string { return msg.Actions }),
		"has_action": unaryBool("has_action", "name", func(name string) bool {
			for _, a := range msg.Actions {
				if a == name || strings.HasPrefix(a, name+":") {
					return true
				}
			}
			return false
		}),
		"clear_actions": nullary("clear_actions", func() starlark.Value {
			msg.Actions = []string{}
			return starlark.None
		}),
	}
}

func (e *scriptEnv) actionPair(name, arg1, arg2 string) *starlark.Builtin {
	return binary(name, arg1, arg2, func(a, b string) (starlark.Value, error) {
		e.msg.Actions = append(e.msg.Actions, fmt.Sprintf("%s:%s:%s", name, a, b))
		return starlark.None, nil
	})
}

// ---------------------------------------------------------------------------
// Header access
// ---------------------------------------------------------------------------

func (e *scriptEnv) headerBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		// get_header is case-insensitive and returns the first occurrence.
		"get_header":   unaryStr("get_header", "name", msg.Get),
		"get_headers":  unaryList("get_headers", "name", msg.GetAll),
		"has_header":   unaryBool("has_header", "name", msg.Has),
		"header_count": unaryInt("header_count", "name", msg.Count),

		"header_names": nullaryList("header_names", func() []string {
			out := make([]string, 0, len(msg.HeaderList))
			for _, h := range msg.HeaderList {
				out = append(out, h.Name)
			}
			return out
		}),

		"all_headers": nullary("all_headers", func() starlark.Value {
			list := make([]starlark.Value, 0, len(msg.HeaderList))
			for _, h := range msg.HeaderList {
				list = append(list, dictOf(
					"name", h.Name,
					"value", h.Value,
					"folded", h.Folded,
					"line", h.LineNum,
				))
			}
			return starlark.NewList(list)
		}),

		"add_header": binary("add_header", "name", "value", func(name, value string) (starlark.Value, error) {
			if strings.ContainsAny(name, "\r\n:\x00") || strings.ContainsAny(value, "\r\n\x00") {
				// Refuse to build the injection the validator flags.
				return nil, fmt.Errorf("add_header: name and value must not contain CR, LF or NUL")
			}
			if msg.ModifiedHeaders == nil {
				msg.ModifiedHeaders = make(map[string]string)
			}
			msg.ModifiedHeaders[name] = value
			msg.Actions = append(msg.Actions, fmt.Sprintf("add_header:%s:%s", name, value))
			return starlark.None, nil
		}),

		"remove_header": unary("remove_header", "name", func(name string) starlark.Value {
			msg.Actions = append(msg.Actions, "remove_header:"+name)
			return starlark.None
		}),

		"header_size":  nullary("header_size", func() starlark.Value { return starlark.MakeInt64(msg.HeaderSize) }),
		"num_envelope": nullaryInt("num_envelope", func() int { return len(msg.EnvelopeSenders) }),
	}
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

func (e *scriptEnv) matchBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"regex_match": binary("regex_match", "pattern", "text", func(pattern, text string) (starlark.Value, error) {
			matched, err := MatchRegex(pattern, text)
			if err != nil {
				return nil, fmt.Errorf("regex_match: %w", err)
			}
			return starlark.Bool(matched), nil
		}),

		"regex_find": binary("regex_find", "pattern", "text", func(pattern, text string) (starlark.Value, error) {
			re, err := CompileRegex(pattern)
			if err != nil {
				return nil, fmt.Errorf("regex_find: %w", err)
			}
			return starlark.String(re.FindString(text)), nil
		}),

		"regex_find_all": starlark.NewBuiltin("regex_find_all",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var pattern, text string
				limit := -1
				if err := starlark.UnpackArgs("regex_find_all", args, kwargs, "pattern", &pattern, "text", &text, "limit?", &limit); err != nil {
					return nil, err
				}
				re, err := CompileRegex(pattern)
				if err != nil {
					return nil, fmt.Errorf("regex_find_all: %w", err)
				}
				return stringList(re.FindAllString(text, limit)), nil
			}),

		"count_matches": binary("count_matches", "pattern", "text", func(pattern, text string) (starlark.Value, error) {
			count, err := CountMatches(pattern, text)
			if err != nil {
				return nil, fmt.Errorf("count_matches: %w", err)
			}
			return starlark.MakeInt(count), nil
		}),

		"header_matches": binary("header_matches", "name", "pattern", func(name, pattern string) (starlark.Value, error) {
			re, err := CompileRegex(pattern)
			if err != nil {
				return nil, fmt.Errorf("header_matches: %w", err)
			}
			for _, value := range msg.GetAll(name) {
				if re.MatchString(value) {
					return starlark.Bool(true), nil
				}
			}
			return starlark.Bool(false), nil
		}),

		"body_matches": unary("body_matches", "pattern", func(pattern string) starlark.Value {
			matched, err := MatchRegex(pattern, msg.SearchText())
			if err != nil {
				return starlark.Bool(false)
			}
			return starlark.Bool(matched)
		}),

		"search_body": unaryBool("search_body", "text", func(needle string) bool {
			return strings.Contains(msg.SearchText(), needle) || strings.Contains(msg.Body, needle)
		}),

		"search_body_ci": unaryBool("search_body_ci", "text", func(needle string) bool {
			return strings.Contains(strings.ToLower(msg.SearchText()), strings.ToLower(needle))
		}),

		"search_headers": unaryBool("search_headers", "text", func(needle string) bool {
			lower := strings.ToLower(needle)
			for _, h := range msg.HeaderList {
				if strings.Contains(strings.ToLower(h.Name+": "+h.Value), lower) {
					return true
				}
			}
			return false
		}),

		"any_match": starlark.NewBuiltin("any_match",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var patterns starlark.Value
				var text string
				if err := starlark.UnpackArgs("any_match", args, kwargs, "patterns", &patterns, "text", &text); err != nil {
					return nil, err
				}
				list, err := stringsFromValue(patterns)
				if err != nil {
					return nil, fmt.Errorf("any_match: %w", err)
				}
				for _, pattern := range list {
					matched, err := MatchRegex(pattern, text)
					if err != nil {
						return nil, fmt.Errorf("any_match: %w", err)
					}
					if matched {
						return starlark.Bool(true), nil
					}
				}
				return starlark.Bool(false), nil
			}),
	}
}

// ---------------------------------------------------------------------------
// Message metadata
// ---------------------------------------------------------------------------

func (e *scriptEnv) metadataBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"getmimetype":    nullaryStr("getmimetype", func() string { return msg.MimeType }),
		"getspamscore":   nullaryFloat("getspamscore", func() float64 { return msg.SpamScore }),
		"getvirusstatus": nullaryStr("getvirusstatus", func() string { return msg.VirusStatus }),
		"av_available":   nullaryBool("av_available", func() bool { return msg.AVAvailable }),
		"av_clean":       nullaryBool("av_clean", func() bool { return msg.AVAvailable && msg.VirusStatus == "clean" }),
		"av_infected":    nullaryBool("av_infected", func() bool { return msg.VirusStatus == "infected" }),
		"av_signature":   nullaryStr("av_signature", func() string { return msg.AVSignature }),
		"yara_available": nullaryBool("yara_available", func() bool { return msg.YARAAvailable }),
		"yara_matches":   nullaryList("yara_matches", func() []string { return msg.YARAMatches }),
		"yara_matched": unaryBool("yara_matched", "rule", func(rule string) bool {
			for _, match := range msg.YARAMatches {
				if match == rule {
					return true
				}
			}
			return false
		}),
		"body_size": nullary("body_size", func() starlark.Value { return starlark.MakeInt64(msg.BodySize) }),
		"message_size": nullary("message_size", func() starlark.Value {
			return starlark.MakeInt64(msg.BodySize + msg.HeaderSize)
		}),
		"get_instance":      nullaryStr("get_instance", func() string { return msg.Instance }),
		"get_instance_name": nullaryStr("get_instance_name", func() string { return msg.InstanceName }),

		"now": nullary("now", func() starlark.Value {
			return starlark.String(msg.RefTime().UTC().Format(time.RFC3339))
		}),

		"date_skew_seconds": nullaryFloat("date_skew_seconds", func() float64 {
			raw := msg.Get("Date")
			if raw == "" {
				return 0
			}
			parsed, err := parseMailDate(raw)
			if err != nil {
				return 0
			}
			return msg.RefTime().Sub(parsed).Seconds()
		}),

		"message_age_seconds": nullaryFloat("message_age_seconds", func() float64 {
			raw := msg.Get("Date")
			if raw == "" {
				return 0
			}
			parsed, err := parseMailDate(raw)
			if err != nil {
				return 0
			}
			age := msg.RefTime().Sub(parsed).Seconds()
			if age < 0 {
				return 0
			}
			return age
		}),

		"parse_date": unary("parse_date", "value", func(raw string) starlark.Value {
			parsed, err := parseMailDate(raw)
			if err != nil {
				return starlark.None
			}
			return starlark.String(parsed.UTC().Format(time.RFC3339))
		}),
	}
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

func (e *scriptEnv) scoreBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"add_score": starlark.NewBuiltin("add_score",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var points float64
				var reason string
				if err := starlark.UnpackArgs("add_score", args, kwargs, "points", &points, "reason?", &reason); err != nil {
					return nil, err
				}
				if reason == "" {
					reason = "unspecified"
				}
				msg.AddScore(points, reason)
				return starlark.Float(msg.Score), nil
			}),

		"get_score":         nullaryFloat("get_score", func() float64 { return msg.Score }),
		"get_score_reasons": nullaryList("get_score_reasons", func() []string { return msg.ScoreReasons }),

		"set_score": starlark.NewBuiltin("set_score",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var value float64
				var reason string
				if err := starlark.UnpackArgs("set_score", args, kwargs, "value", &value, "reason?", &reason); err != nil {
					return nil, err
				}
				msg.Score = value
				if reason != "" {
					msg.ScoreReasons = append(msg.ScoreReasons, fmt.Sprintf("=%.1f %s", value, reason))
				}
				return starlark.Float(msg.Score), nil
			}),

		"reset_score": nullary("reset_score", func() starlark.Value {
			msg.Score = 0
			msg.ScoreReasons = []string{}
			return starlark.None
		}),
	}
}

// ---------------------------------------------------------------------------
// Named lists
// ---------------------------------------------------------------------------

func (e *scriptEnv) listBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"in_list": binary("in_list", "list_name", "value", func(name, value string) (starlark.Value, error) {
			entries, ok := msg.Lists[name]
			if !ok {
				return starlark.Bool(false), nil
			}
			return starlark.Bool(entries[strings.ToLower(strings.TrimSpace(value))]), nil
		}),

		"list_names": nullaryList("list_names", func() []string {
			names := make([]string, 0, len(msg.Lists))
			for name := range msg.Lists {
				names = append(names, name)
			}
			sort.Strings(names)
			return names
		}),

		"list_size": unaryInt("list_size", "list_name", func(name string) int {
			return len(msg.Lists[name])
		}),

		// domain_in_list matches an address or hostname against a list of
		// domains, honouring subdomains so one entry covers a whole zone.
		"domain_in_list": binary("domain_in_list", "list_name", "value", func(name, value string) (starlark.Value, error) {
			entries, ok := msg.Lists[name]
			if !ok {
				return starlark.Bool(false), nil
			}
			host := value
			if strings.Contains(value, "@") {
				host = DomainOf(value)
			}
			host = strings.ToLower(strings.TrimSpace(host))
			if host == "" {
				return starlark.Bool(false), nil
			}
			for entry := range entries {
				if IsSubdomainOf(host, entry) {
					return starlark.Bool(true), nil
				}
			}
			return starlark.Bool(false), nil
		}),
	}
}

// ---------------------------------------------------------------------------
// Legacy compatibility
//
// These exist so that scripts written against the original MailScript
// function set keep running unchanged.
// ---------------------------------------------------------------------------

func (e *scriptEnv) legacyBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"get_recipient_did": nullaryStr("get_recipient_did", func() string { return msg.SenderDID }),

		"get_content_filter":      nullaryStr("get_content_filter", func() string { return msg.ContentFilter }),
		"get_content_filter_name": nullaryStr("get_content_filter_name", func() string { return msg.ContentFilterName }),
		"get_content_filter_rules": nullary("get_content_filter_rules", func() starlark.Value {
			return stringDict(msg.ContentFilterRules)
		}),
		"set_content_filter_rules": unary("set_content_filter_rules", "rule", func(rule string) starlark.Value {
			msg.Actions = append(msg.Actions, "set_filter_rules:"+rule)
			return starlark.Bool(true)
		}),
	}
}

func parseMailDate(raw string) (time.Time, error) {
	return mailParseDate(strings.TrimSpace(raw))
}

// BuiltinNames returns every builtin exposed to rule scripts, for
// documentation and tooling. It is derived from the live registration, so a
// generated reference cannot drift from the implementation.
func BuiltinNames() []string {
	env := &scriptEnv{msg: NewMessageContext(), opts: DefaultOptions()}
	predeclared := env.predeclared()

	names := make([]string, 0, len(predeclared))
	for name := range predeclared {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
