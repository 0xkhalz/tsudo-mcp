package policy

import (
	"errors"
	"slices"
	"testing"
)

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		command  string
		args     []string
		want     Normalized
		wantDeny bool
	}{
		// Command and argument validation
		{
			name:     "empty command rejected",
			command:  "",
			wantDeny: true,
		},
		{
			name:     "whitespace in command rejected",
			command:  "rm -rf",
			wantDeny: true,
		},
		{
			name:     "tab in command rejected",
			command:  "ls\t-la",
			wantDeny: true,
		},
		{
			name:     "NUL in command rejected",
			command:  "ls\x00",
			wantDeny: true,
		},
		{
			name:     "NUL in arg rejected",
			command:  "ls",
			args:     []string{"/tmp\x00foo"},
			wantDeny: true,
		},

		// Sudo normalization
		{
			name:    "sudo pacman -Syu normalized",
			command: "sudo",
			args:    []string{"pacman", "-Syu"},
			want:    Normalized{Command: "pacman", Args: []string{"-Syu"}},
		},
		{
			name:    "sudo with double dash normalized",
			command: "/usr/bin/sudo",
			args:    []string{"--", "systemctl", "status", "sshd"},
			want:    Normalized{Command: "systemctl", Args: []string{"status", "sshd"}},
		},
		{
			name:     "sudo with -u flag rejected",
			command:  "sudo",
			args:     []string{"-u", "root", "id"},
			wantDeny: true,
		},
		{
			name:     "sudo with -i flag rejected",
			command:  "sudo",
			args:     []string{"-i"},
			wantDeny: true,
		},
		{
			name:     "sudo with -s flag rejected",
			command:  "sudo",
			args:     []string{"-s"},
			wantDeny: true,
		},
		{
			name:     "sudo alone rejected",
			command:  "sudo",
			wantDeny: true,
		},
		{
			name:     "sudo double dash alone rejected",
			command:  "sudo",
			args:     []string{"--"},
			wantDeny: true,
		},
		{
			name:     "double sudo caught by hard denylist",
			command:  "sudo",
			args:     []string{"sudo", "id"},
			wantDeny: true,
		},
		{
			name:     "sudo promoted empty command rejected",
			command:  "sudo",
			args:     []string{""},
			wantDeny: true,
		},
		{
			name:     "sudo promoted whitespace command rejected",
			command:  "sudo",
			args:     []string{"echo hi"},
			wantDeny: true,
		},

		// Recursive rm checks
		{
			name:     "rm -rf //etc/ denied",
			command:  "/usr/bin/rm",
			args:     []string{"-rf", "//etc/"},
			wantDeny: true,
		},
		{
			name:     "rm --recursive /etc/. denied",
			command:  "rm",
			args:     []string{"--recursive", "/etc/."},
			wantDeny: true,
		},
		{
			name:     "rm -fr / denied",
			command:  "rm",
			args:     []string{"-fr", "/"},
			wantDeny: true,
		},
		{
			name:     "rm -rf /* denied",
			command:  "rm",
			args:     []string{"-rf", "/*"},
			wantDeny: true,
		},
		{
			name:     "rm -rf /etc/* denied",
			command:  "rm",
			args:     []string{"-rf", "/etc/*"},
			wantDeny: true,
		},
		{
			name:     "rm -rf -- /etc denied",
			command:  "rm",
			args:     []string{"-rf", "--", "/etc"},
			wantDeny: true,
		},
		{
			name:     "rm -vRf /var denied",
			command:  "rm",
			args:     []string{"-vRf", "/var"},
			wantDeny: true,
		},
		{
			name:    "rm -rf /tmp/safe allowed",
			command: "rm",
			args:    []string{"-rf", "/tmp/safe"},
			want:    Normalized{Command: "rm", Args: []string{"-rf", "/tmp/safe"}},
		},
		{
			name:    "rm -rf /var/cache/pacman/pkg/corrupt allowed",
			command: "rm",
			args:    []string{"-rf", "/var/cache/pacman/pkg/corrupt"},
			want:    Normalized{Command: "rm", Args: []string{"-rf", "/var/cache/pacman/pkg/corrupt"}},
		},
		{
			name:     "rm --no-preserve-root /tmp/x denied",
			command:  "rm",
			args:     []string{"--no-preserve-root", "/tmp/x"},
			wantDeny: true,
		},
		{
			name:    "non-recursive rm on /etc/motd allowed",
			command: "rm",
			args:    []string{"/etc/motd"},
			want:    Normalized{Command: "rm", Args: []string{"/etc/motd"}},
		},

		// dd and of=/dev/...
		{
			name:     "dd denied",
			command:  "dd",
			args:     []string{"if=/dev/zero", "of=/dev/sda"},
			wantDeny: true,
		},
		{
			name:     "dd even with safe path denied",
			command:  "dd",
			args:     []string{"if=/dev/zero", "of=/tmp/file"},
			wantDeny: true,
		},
		{
			name:     "any command with of=/dev/nvme0n1 denied",
			command:  "foo",
			args:     []string{"of=/dev/nvme0n1"},
			wantDeny: true,
		},
		{
			name:     "any command with of=/dev denied",
			command:  "foo",
			args:     []string{"of=/dev"},
			wantDeny: true,
		},
		{
			name:    "any command with of=/tmp/out allowed",
			command: "foo",
			args:    []string{"of=/tmp/out"},
			want:    Normalized{Command: "foo", Args: []string{"of=/tmp/out"}},
		},

		// Disk destruction tools
		{
			name:     "mkfs denied",
			command:  "mkfs",
			wantDeny: true,
		},
		{
			name:     "mkfs.ext4 denied",
			command:  "mkfs.ext4",
			args:     []string{"/dev/sda1"},
			wantDeny: true,
		},
		{
			name:     "wipefs denied",
			command:  "wipefs",
			wantDeny: true,
		},
		{
			name:     "fdisk denied",
			command:  "fdisk",
			wantDeny: true,
		},
		{
			name:     "parted denied",
			command:  "parted",
			wantDeny: true,
		},
		{
			name:     "gdisk denied",
			command:  "gdisk",
			wantDeny: true,
		},
		{
			name:     "shred denied",
			command:  "shred",
			wantDeny: true,
		},

		// Recursive chmod/chown/chgrp
		{
			name:     "chmod -R 777 /etc denied",
			command:  "chmod",
			args:     []string{"-R", "777", "/etc"},
			wantDeny: true,
		},
		{
			name:     "chown -R user:user /usr/ denied",
			command:  "chown",
			args:     []string{"-R", "user:user", "/usr/"},
			wantDeny: true,
		},
		{
			name:     "chgrp --recursive wheel / denied",
			command:  "chgrp",
			args:     []string{"--recursive", "wheel", "/"},
			wantDeny: true,
		},
		{
			name:     "chmod bundled -vR on /boot denied",
			command:  "chmod",
			args:     []string{"-vR", "700", "/boot"},
			wantDeny: true,
		},
		{
			name:     "chmod -R -- /etc denied",
			command:  "chmod",
			args:     []string{"-R", "--", "/etc"},
			wantDeny: true,
		},
		{
			name:    "chmod -R 644 /tmp/test allowed",
			command: "chmod",
			args:    []string{"-R", "644", "/tmp/test"},
			want:    Normalized{Command: "chmod", Args: []string{"-R", "644", "/tmp/test"}},
		},
		{
			name:    "chmod -r (lowercase) on /etc allowed",
			command: "chmod",
			args:    []string{"-r", "/etc"},
			want:    Normalized{Command: "chmod", Args: []string{"-r", "/etc"}},
		},

		// Privilege/auth/self-recursion
		{
			name:     "visudo denied",
			command:  "visudo",
			wantDeny: true,
		},
		{
			name:     "passwd denied",
			command:  "passwd",
			wantDeny: true,
		},
		{
			name:     "chpasswd denied",
			command:  "chpasswd",
			wantDeny: true,
		},
		{
			name:     "su denied",
			command:  "su",
			wantDeny: true,
		},
		{
			name:     "tsudo denied",
			command:  "tsudo",
			wantDeny: true,
		},

		// Shell blocker & AllowShell overrides
		{
			name:     "sh blocked by default",
			command:  "sh",
			args:     []string{"-c", "echo hi"},
			wantDeny: true,
		},
		{
			name:     "bash blocked by default",
			command:  "/bin/bash",
			args:     []string{"-c", "id"},
			wantDeny: true,
		},
		{
			name:     "fish blocked by default",
			command:  "fish",
			wantDeny: true,
		},
		{
			name:     "eval blocked by default",
			command:  "eval",
			wantDeny: true,
		},
		{
			name:    "bash allowed when AllowShell=true",
			cfg:     Config{AllowShell: true},
			command: "/bin/bash",
			args:    []string{"-c", "id"},
			want:    Normalized{Command: "/bin/bash", Args: []string{"-c", "id"}},
		},
		{
			name:     "dd still denied even when AllowShell=true and in Allowlist",
			cfg:      Config{AllowShell: true, Allowlist: []string{"dd"}},
			command:  "dd",
			args:     []string{"if=/dev/zero", "of=/tmp/x"},
			wantDeny: true,
		},
		{
			name:     "rm -rf / still denied even when AllowShell=true and in Allowlist",
			cfg:      Config{AllowShell: true, Allowlist: []string{"rm"}},
			command:  "rm",
			args:     []string{"-rf", "/"},
			wantDeny: true,
		},

		// Allowlist checks
		{
			name:    "allowlist matches base name",
			cfg:     Config{Allowlist: []string{"systemctl"}},
			command: "/usr/bin/systemctl",
			args:    []string{"restart", "sshd"},
			want:    Normalized{Command: "/usr/bin/systemctl", Args: []string{"restart", "sshd"}},
		},
		{
			name:     "allowlist rejects unlisted command",
			cfg:      Config{Allowlist: []string{"systemctl"}},
			command:  "pacman",
			args:     []string{"-Syu"},
			wantDeny: true,
		},
		{
			name:    "allowlist exact path matches exact command",
			cfg:     Config{Allowlist: []string{"/usr/bin/pacman"}},
			command: "/usr/bin/pacman",
			args:    []string{"-Syu"},
			want:    Normalized{Command: "/usr/bin/pacman", Args: []string{"-Syu"}},
		},
		{
			name:     "allowlist exact path rejects base-only command",
			cfg:      Config{Allowlist: []string{"/usr/bin/pacman"}},
			command:  "pacman",
			args:     []string{"-Syu"},
			wantDeny: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := New(tc.cfg)
			got, err := p.Evaluate(tc.command, tc.args)
			if tc.wantDeny {
				if err == nil {
					t.Fatalf("expected denial, got %+v", got)
				}
				if !errors.Is(err, ErrDenied) {
					t.Fatalf("expected errors.Is(err, ErrDenied), got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Command != tc.want.Command {
				t.Fatalf("Command = %q, want %q", got.Command, tc.want.Command)
			}
			if !slices.Equal(got.Args, tc.want.Args) {
				t.Fatalf("Args = %v, want %v", got.Args, tc.want.Args)
			}
		})
	}
}

func TestEvaluateDoesNotMutateInputArgs(t *testing.T) {
	p := New(Config{})
	origArgs := []string{"systemctl", "status", "sshd"}
	snapshot := slices.Clone(origArgs)

	got, err := p.Evaluate("sudo", origArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(origArgs, snapshot) {
		t.Fatalf("input args mutated: got %v, want %v", origArgs, snapshot)
	}

	got.Args[0] = "MUTATED"
	if !slices.Equal(origArgs, snapshot) {
		t.Fatalf("mutating returned Args mutated input args: got %v, want %v", origArgs, snapshot)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Run("unset defaults", func(t *testing.T) {
		t.Setenv("TSUDO_MCP_ALLOW_SHELL", "")
		t.Setenv("TSUDO_MCP_ALLOWLIST", "")
		cfg := ConfigFromEnv()
		if cfg.AllowShell {
			t.Fatalf("AllowShell = true, want false")
		}
		if len(cfg.Allowlist) != 0 {
			t.Fatalf("Allowlist = %v, want empty", cfg.Allowlist)
		}
	})

	t.Run("blank allowlist treated as empty", func(t *testing.T) {
		t.Setenv("TSUDO_MCP_ALLOW_SHELL", "0")
		t.Setenv("TSUDO_MCP_ALLOWLIST", "  ,  ,\t ")
		cfg := ConfigFromEnv()
		if cfg.AllowShell {
			t.Fatalf("AllowShell = true, want false")
		}
		if len(cfg.Allowlist) != 0 {
			t.Fatalf("Allowlist = %v, want empty", cfg.Allowlist)
		}
	})

	t.Run("populated values", func(t *testing.T) {
		t.Setenv("TSUDO_MCP_ALLOW_SHELL", "1")
		t.Setenv("TSUDO_MCP_ALLOWLIST", " systemctl , , /usr/bin/pacman , journalctl ")
		cfg := ConfigFromEnv()
		if !cfg.AllowShell {
			t.Fatalf("AllowShell = false, want true")
		}
		want := []string{"systemctl", "/usr/bin/pacman", "journalctl"}
		if !slices.Equal(cfg.Allowlist, want) {
			t.Fatalf("Allowlist = %v, want %v", cfg.Allowlist, want)
		}
	})
}
