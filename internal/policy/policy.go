// Package policy enforces command normalization, shell blocking, hard
// denylists, and optional allowlists before privileged execution.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// ErrDenied is returned (wrapped) whenever the policy rejects a command.
var ErrDenied = errors.New("policy denied")

// Normalized represents a validated, sudo-unwrapped command and a defensive
// copy of its argument slice.
type Normalized struct {
	Command string
	Args    []string
}

// Config configures Policy behavior.
type Config struct {
	AllowShell bool
	Allowlist  []string
}

// Evaluator validates and normalizes a privileged command invocation.
type Evaluator interface {
	Evaluate(command string, args []string) (Normalized, error)
}

// Policy implements Evaluator using a hard denylist, shell blocker, and
// optional allowlist.
type Policy struct {
	allowShell   bool
	hasAllowlist bool
	allowBase    map[string]struct{}
	allowExact   map[string]struct{}
}

var (
	_ Evaluator = (*Policy)(nil)

	hardDeniedCommands = map[string]struct{}{
		"visudo":   {},
		"passwd":   {},
		"chpasswd": {},
		"sudo":     {},
		"su":       {},
		"tsudo":    {},
		"mkfs":     {},
		"wipefs":   {},
		"fdisk":    {},
		"parted":   {},
		"gdisk":    {},
		"shred":    {},
		"dd":       {},
	}

	shellCommands = map[string]struct{}{
		"sh":   {},
		"bash": {},
		"zsh":  {},
		"fish": {},
		"dash": {},
		"ksh":  {},
		"csh":  {},
		"tcsh": {},
		"eval": {},
	}

	sensitivePaths = buildSensitivePaths([]string{
		"/",
		"/etc",
		"/bin",
		"/sbin",
		"/usr",
		"/var",
		"/home",
		"/root",
		"/boot",
		"/dev",
		"/proc",
		"/sys",
	})
)

func buildSensitivePaths(roots []string) map[string]struct{} {
	m := make(map[string]struct{}, len(roots)*2)
	for _, root := range roots {
		m[root] = struct{}{}
		m[filepath.Join(root, "*")] = struct{}{}
	}
	return m
}

// ConfigFromEnv loads policy configuration from TSUDO_MCP_ALLOW_SHELL and
// TSUDO_MCP_ALLOWLIST.
func ConfigFromEnv() Config {
	cfg := Config{
		AllowShell: os.Getenv("TSUDO_MCP_ALLOW_SHELL") == "1",
	}
	raw := os.Getenv("TSUDO_MCP_ALLOWLIST")
	if strings.TrimSpace(raw) == "" {
		return cfg
	}
	for part := range strings.SplitSeq(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			cfg.Allowlist = append(cfg.Allowlist, trimmed)
		}
	}
	return cfg
}

// New constructs a Policy from cfg, copying allowlist entries defensively.
func New(cfg Config) *Policy {
	p := &Policy{
		allowShell:   cfg.AllowShell,
		hasAllowlist: len(cfg.Allowlist) > 0,
	}
	if p.hasAllowlist {
		p.allowBase = make(map[string]struct{}, len(cfg.Allowlist))
		p.allowExact = make(map[string]struct{}, len(cfg.Allowlist))
		for _, entry := range cfg.Allowlist {
			if strings.Contains(entry, "/") {
				p.allowExact[entry] = struct{}{}
			} else {
				p.allowBase[entry] = struct{}{}
			}
		}
	}
	return p
}

// Evaluate validates, normalizes, and checks a command and its arguments
// without mutating the caller's args slice.
func (p *Policy) Evaluate(command string, args []string) (Normalized, error) {
	if err := validateCommand(command); err != nil {
		return Normalized{}, err
	}
	if err := validateArgs(args); err != nil {
		return Normalized{}, err
	}

	copiedArgs := slices.Clone(args)

	cmd, normArgs, err := normalizeSudo(command, copiedArgs)
	if err != nil {
		return Normalized{}, err
	}

	base := filepath.Base(cmd)

	if err := checkHardDenylist(base, normArgs); err != nil {
		return Normalized{}, err
	}

	if !p.allowShell {
		if _, blocked := shellCommands[base]; blocked {
			return Normalized{}, fmt.Errorf("%w: shell command %q is blocked", ErrDenied, base)
		}
	}

	if p.hasAllowlist && !p.isAllowed(cmd, base) {
		return Normalized{}, fmt.Errorf("%w: command %q is not in allowlist", ErrDenied, cmd)
	}

	return Normalized{
		Command: cmd,
		Args:    slices.Clone(normArgs),
	}, nil
}

func (p *Policy) isAllowed(cmd, base string) bool {
	if _, ok := p.allowExact[cmd]; ok {
		return true
	}
	_, ok := p.allowBase[base]
	return ok
}

func validateCommand(command string) error {
	if command == "" {
		return fmt.Errorf("%w: empty command", ErrDenied)
	}
	if strings.IndexByte(command, 0) >= 0 {
		return fmt.Errorf("%w: NUL byte in command", ErrDenied)
	}
	if strings.IndexFunc(command, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%w: whitespace in command %q", ErrDenied, command)
	}
	return nil
}

func validateArgs(args []string) error {
	for i, arg := range args {
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("%w: NUL byte in argument %d", ErrDenied, i)
		}
	}
	return nil
}

func normalizeSudo(command string, args []string) (string, []string, error) {
	if filepath.Base(command) != "sudo" {
		return command, args, nil
	}
	if len(args) == 0 {
		return "", nil, fmt.Errorf("%w: bare sudo without command", ErrDenied)
	}

	var nextCmd string
	var nextArgs []string
	switch {
	case args[0] == "--":
		if len(args) < 2 {
			return "", nil, fmt.Errorf("%w: sudo -- without command", ErrDenied)
		}
		nextCmd = args[1]
		nextArgs = args[2:]
	case strings.HasPrefix(args[0], "-"):
		return "", nil, fmt.Errorf("%w: sudo flag %q is disallowed", ErrDenied, args[0])
	default:
		nextCmd = args[0]
		nextArgs = args[1:]
	}

	if err := validateCommand(nextCmd); err != nil {
		return "", nil, err
	}
	return nextCmd, nextArgs, nil
}

func checkHardDenylist(base string, args []string) error {
	if _, denied := hardDeniedCommands[base]; denied {
		return fmt.Errorf("%w: command %q is hard-denied", ErrDenied, base)
	}
	if strings.HasPrefix(base, "mkfs.") {
		return fmt.Errorf("%w: disk format command %q is hard-denied", ErrDenied, base)
	}

	for _, arg := range args {
		if target, ok := strings.CutPrefix(arg, "of="); ok {
			cleaned := filepath.Clean(target)
			if cleaned == "/dev" || strings.HasPrefix(cleaned, "/dev/") {
				return fmt.Errorf("%w: output target %q in /dev is hard-denied", ErrDenied, arg)
			}
		}
	}

	switch base {
	case "rm", "chmod", "chown", "chgrp":
		return checkRecursivePathCommand(base, args)
	}
	return nil
}

func checkRecursivePathCommand(base string, args []string) error {
	recursive := false
	afterDash := false
	var targets []string

	for _, arg := range args {
		if afterDash {
			targets = append(targets, arg)
			continue
		}
		if arg == "--" {
			afterDash = true
			continue
		}
		if base == "rm" && arg == "--no-preserve-root" {
			return fmt.Errorf("%w: rm --no-preserve-root is hard-denied", ErrDenied)
		}
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			if isRecursiveFlag(base, arg) {
				recursive = true
			}
			continue
		}
		targets = append(targets, arg)
	}

	if !recursive {
		return nil
	}
	for _, target := range targets {
		if isSensitivePath(target) {
			return fmt.Errorf("%w: recursive %s on sensitive path %q is hard-denied", ErrDenied, base, target)
		}
	}
	return nil
}

func isRecursiveFlag(base, arg string) bool {
	if arg == "--recursive" {
		return true
	}
	if strings.HasPrefix(arg, "--") {
		return false
	}
	flags := arg[1:]
	if base == "rm" {
		return strings.ContainsAny(flags, "rR")
	}
	return strings.ContainsRune(flags, 'R')
}

func isSensitivePath(p string) bool {
	_, ok := sensitivePaths[filepath.Clean(p)]
	return ok
}
