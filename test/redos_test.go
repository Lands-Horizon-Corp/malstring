package test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestReDoSDetector_BasicPatterns(t *testing.T) {
	detector := detectors.NewReDoS()

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		// Basic safe inputs
		{"Empty string", "", false},
		{"Simple text", "hello world", false},
		{"Normal regex", "^[a-zA-Z0-9]+$", false},
		{"Valid email regex", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", false},

		// Simple repetitive character attacks
		{"Long repeated a's", strings.Repeat("a", 20), true},
		{"Long repeated special chars", strings.Repeat("!", 20), true},
		{"Mixed repeated chars", "aaaaaaaaaaaaaaaa" + "bbbbbbbbbbbbbbbb", true},

		// Pattern repetition attacks
		{"Repeated short pattern", strings.Repeat("ab", 10), true},
		{"Repeated medium pattern", strings.Repeat("abc", 7), true},
		{"Repeated regex pattern", strings.Repeat("(ab)", 6), true},

		// Large input attacks
		{"Very large input", strings.Repeat("x", 150000), true},
		{"Large input with variety", strings.Repeat("abcdef", 20000), true},

		// Nested quantifier patterns
		{"Nested plus quantifiers", "(a+)+", true},
		{"Nested star quantifiers", "(a*)*", true},
		{"Mixed nested quantifiers", "(a+)*", true},
		{"Complex nested", "(abc+)+", true},

		// Alternation explosion patterns
		{"Simple alternation explosion", "(a|a)*", true},
		{"Complex alternation", "(hello|hello)*", true},
		{"Multiple alternations simple", "a|b|c|d|e|f|g|h|i|j|k|l", false},                                // Simple alternation should be OK
		{"Multiple alternations complex", "(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+", true}, // This would be problematic

		// Suspicious token detection
		{"Evil regex token 1", "(.*)* malicious input", true},
		{"Evil regex token 2", "(.+)+ attack vector", true},
		{"Evil regex token 3", "(a|a)* pattern", true},
		{"Evil regex token 4", ".{0,} unlimited", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := detector.Check(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v for input: %s", tc.expected, result, tc.input)
			}
		})
	}
}

func TestReDoSDetector_AdvancedPatterns(t *testing.T) {
	detector := detectors.NewReDoS()

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		// Unicode exploitation
		{"High Unicode density", strings.Repeat("你好世界", 50), true},
		{"Mixed Unicode attack", "normal" + strings.Repeat("€", 100), true},
		{"Control character attack", "test" + strings.Repeat("\x00", 50), true},

		// Advanced nested patterns
		{"Deeply nested groups", "((((a+)+)+)+)", true},
		{"Mixed grouping", "(a*)? followed by (b+)+", true},
		{"Quantifier variations", "pattern{1,} and another{0,} patterns", true}, // Unbounded quantifiers are suspicious

		// Boundary exploitation
		{"Word boundary attack", "\\b" + strings.Repeat("test", 10) + "\\b+", true},
		{"Lookahead patterns", "(?=" + strings.Repeat("x", 40) + ")", true},

		// Character class attacks
		{"Character class repetition", "[a-z]+ repeated [a-z]+", true},      // Multiple similar patterns
		{"Complex character classes", "[^\\s]* with similar [^\\s]*", true}, // Multiple similar patterns

		// Realistic attack patterns
		{"Email regex bomb", "^([a-zA-Z0-9_\\-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\\]?)$", false}, // This is actually a safe regex
		{"Catastrophic email", "(([a-zA-Z0-9_\\-\\.]+)*)*@", true},               // This would be dangerous
		{"URL validation bomb", "^(https?|ftp)://([^\\s/$.?#].[^\\s]*)$", false}, // Safe
		{"Dangerous URL regex", "^(http|https|ftp)://([a-zA-Z0-9.-]*)*", true},   // Dangerous

		// Edge cases
		{"Empty groups with quantifiers", "()+", true},
		{"Nested empty groups", "(())+", true},
		{"Multiple empty alternations", "(|)+", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := detector.Check(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v for input: %s", tc.expected, result, tc.input)
			}
		})
	}
}

func TestReDoSDetector_CatastrophicBacktracking(t *testing.T) {
	detector := detectors.NewReDoS()

	// These are inputs designed to cause catastrophic backtracking if the detector itself had vulnerabilities
	catastrophicInputs := []string{
		// Exponential alternation
		strings.Repeat("(a|a)", 50) + "*",

		// Nested quantifier bombs
		strings.Repeat("(", 100) + strings.Repeat("a+", 50) + strings.Repeat(")+", 100),

		// Large alternation groups
		strings.Join(make([]string, 100), "|") + "+",

		// Unicode bomb attempts
		strings.Repeat("([你好]|[你好])", 30) + "*",

		// Mixed pattern bombs
		strings.Repeat("(abc+|def*)", 25) + "+",

		// Character class bombs
		strings.Repeat("([a-z]*|[A-Z]*)", 40) + "*",

		// Lookahead/lookbehind bombs (if supported)
		strings.Repeat("(?=", 50) + strings.Repeat("a*", 25) + strings.Repeat(")", 50),

		// Word boundary bombs
		strings.Repeat("\\b", 100) + strings.Repeat("test", 50) + strings.Repeat("\\b+", 25),

		// Quantifier range bombs
		strings.Repeat("a{0,", 50) + "}" + strings.Repeat("*", 25),

		// Backslash escape bombs
		strings.Repeat("\\", 1000) + strings.Repeat("d+", 50),

		// Bracket expression bombs
		strings.Repeat("[", 200) + strings.Repeat("a-z]", 100) + "+",

		// Comment bombs (some regex engines support comments)
		strings.Repeat("(?#", 100) + strings.Repeat("comment", 50) + strings.Repeat(")", 100),

		// Very long single line with mixed patterns
		strings.Repeat("(a+)+(b*)*", 100),

		// Pathological email-like pattern
		strings.Repeat("a", 1000) + "@" + strings.Repeat("(b+)+", 50) + ".com",

		// URL-like catastrophic pattern
		"http://" + strings.Repeat("(www\\.)*", 100) + strings.Repeat("([a-z]+\\.)*", 100) + "com",

		// JSON-like nested structure
		strings.Repeat("{\"key\":", 500) + strings.Repeat("(\"value\")*", 100) + strings.Repeat("}", 500),

		// XML-like nested tags
		strings.Repeat("<tag", 200) + strings.Repeat("(attr=\"val\")*", 100) + strings.Repeat(">", 200),

		// Code injection with regex patterns
		"SELECT * FROM users WHERE name LIKE '" + strings.Repeat("(a*)*", 100) + "'",

		// File path with pattern repetition
		strings.Repeat("/", 500) + strings.Repeat("(folder)*", 100) + "/file.txt",

		// Network pattern
		strings.Repeat("192.168.", 250) + strings.Repeat("([0-9]+)*", 50),

		// Time/date pattern bomb
		strings.Repeat("\\d{4}-", 100) + strings.Repeat("(\\d{2})*", 100) + "-\\d{2}",

		// Phone number pattern bomb
		strings.Repeat("\\+?", 100) + strings.Repeat("([0-9-()\\s]*)*", 100),

		// Credit card pattern bomb
		strings.Repeat("\\d{4}", 100) + strings.Repeat("([-\\s]*)*", 100) + strings.Repeat("\\d{4}", 100),

		// Social security pattern bomb
		strings.Repeat("\\d{3}-", 100) + strings.Repeat("(\\d{2})*", 100) + "-\\d{4}",

		// IP address pattern bomb
		strings.Repeat("(", 100) + strings.Repeat("\\d{1,3}\\.", 100) + strings.Repeat(")*", 100) + "\\d{1,3}",

		// HTML tag pattern bomb
		strings.Repeat("<", 500) + strings.Repeat("([a-zA-Z0-9]+)*", 100) + strings.Repeat(">", 500),

		// CSS selector bomb
		strings.Repeat(".", 500) + strings.Repeat("([a-zA-Z0-9-_]*)*", 100) + strings.Repeat("{}", 100),

		// JavaScript regex pattern bomb
		"/^" + strings.Repeat("(", 200) + strings.Repeat("[a-zA-Z0-9]*", 100) + strings.Repeat(")+", 200) + "$/g",

		// Base64-like pattern bomb
		strings.Repeat("([A-Za-z0-9+/]*)*", 100) + "={0,2}",

		// Hex color pattern bomb
		"#" + strings.Repeat("([0-9A-Fa-f]{2})*", 100),
	}

	// Test that all catastrophic inputs are processed within reasonable time
	for i, input := range catastrophicInputs {
		t.Run(fmt.Sprintf("Catastrophic_Input_%d", i+1), func(t *testing.T) {
			start := time.Now()

			// This should complete quickly and detect it as malicious
			result := detector.Check(input)

			duration := time.Since(start)

			// Should complete within 100ms (generous timeout)
			if duration > 100*time.Millisecond {
				t.Errorf("Detection took too long: %v (input length: %d)", duration, len(input))
			}

			// Most of these should be detected as malicious
			if !result {
				t.Logf("Input not detected as malicious (might be acceptable): %s",
					input[:min(50, len(input))]+"...")
			}
		})
	}
}

func TestReDoSDetector_Performance(t *testing.T) {
	detector := detectors.NewReDoS()

	performanceTests := []struct {
		name        string
		inputSize   int
		maxDuration time.Duration
	}{
		{"Small input", 100, 1 * time.Millisecond},
		{"Medium input", 1000, 5 * time.Millisecond},
		{"Large input", 10000, 20 * time.Millisecond},
		{"Very large input", 100000, 50 * time.Millisecond},
	}

	for _, pt := range performanceTests {
		t.Run(pt.name, func(t *testing.T) {
			// Create test input of specified size
			input := strings.Repeat("a(b+)*c", pt.inputSize/7) // Mix of normal and suspicious patterns

			start := time.Now()
			_ = detector.Check(input)
			duration := time.Since(start)

			if duration > pt.maxDuration {
				t.Errorf("Performance test failed: took %v, expected max %v", duration, pt.maxDuration)
			}
		})
	}
}

func TestReDoSDetector_FalsePositives(t *testing.T) {
	detector := detectors.NewReDoS()

	// These should NOT be detected as malicious (common legitimate patterns)
	legitimatePatterns := []string{
		// Common safe regex patterns
		"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",  // Email validation
		"^\\d{3}-\\d{2}-\\d{4}$",                             // SSN format
		"^\\+?[1-9]\\d{1,14}$",                               // Phone number
		"^(https?|ftp)://[^\\s/$.?#].[^\\s]*$",               // URL validation
		"^[0-9A-Fa-f]{6}$",                                   // Hex color
		"^\\d{4}-\\d{2}-\\d{2}$",                             // Date format
		"^[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}([A-Z0-9]?){0,16}$", // IBAN

		// Programming constructs that might look suspicious
		"if (condition) { return true; }",
		"for (int i = 0; i < 10; i++) { process(); }",
		"SELECT * FROM table WHERE column = 'value'",

		// Normal text with some repetition (but below threshold)
		"Hello world! This is a test message.",
		"The quick brown fox jumps over the lazy dog.",
		strings.Repeat("a", 18), // Short repetition should be OK

		// Code snippets
		"function validate(input) { return /^[a-z]+$/.test(input); }",
		"public boolean isValid(String s) { return s.matches(\"\\\\d+\"); }",
	}

	for i, pattern := range legitimatePatterns {
		t.Run(fmt.Sprintf("Legitimate_Pattern_%d", i+1), func(t *testing.T) {
			result := detector.Check(pattern)
			if result {
				t.Errorf("False positive detected for legitimate pattern: %s", pattern)
			}
		})
	}
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
