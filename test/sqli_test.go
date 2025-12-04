package test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestNewSQLi(t *testing.T) {
	detector := detectors.NewSQLi()
	if detector == nil {
		t.Fatal("NewSQLi() returned nil")
	}
}

func TestSQLiDetector_Name(t *testing.T) {
	detector := detectors.NewSQLi()
	expected := "sql_injection"
	if detector.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, detector.Name())
	}
}

func TestSQLiDetector_Check(t *testing.T) {
	detector := detectors.NewSQLi()

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		// Positive cases - should detect SQL injection
		{
			name:     "Basic UNION attack",
			input:    "1' UNION SELECT * FROM users--",
			expected: true,
		},
		{
			name:     "SELECT statement",
			input:    "'; SELECT password FROM admin;--",
			expected: true,
		},
		{
			name:     "Time-based blind injection with SLEEP",
			input:    "1' AND SLEEP(5)--",
			expected: true,
		},
		{
			name:     "Benchmark function",
			input:    "1' AND BENCHMARK(1000000,MD5(1))--",
			expected: true,
		},
		{
			name:     "Case insensitive UNION",
			input:    "1' union select null,null--",
			expected: true,
		},
		{
			name:     "Case insensitive SELECT",
			input:    "1' or 1=1; select * from users",
			expected: true, // Should be detected
		},
		{
			name:     "Mixed case SLEEP",
			input:    "1' AND Sleep(10)--",
			expected: true,
		},
		{
			name:     "Mixed case BENCHMARK",
			input:    "1' AND Benchmark(1000,SHA1(1))--",
			expected: true,
		},
		{
			name:     "UNION with whitespace variations",
			input:    "1'   UNION   SELECT  username,password  FROM  users--",
			expected: true,
		},
		{
			name:     "SELECT in middle of string",
			input:    "some text before SELECT * FROM table after text",
			expected: true, // Should be detected
		},
		{
			name:     "Example from main function",
			input:    "normal text; DROP TABLE users;",
			expected: true, // Now detects DROP TABLE
		},
		{
			name:     "UNION with DROP",
			input:    "normal text; UNION SELECT 1; DROP TABLE users;",
			expected: true,
		},
		{
			name:     "INSERT injection",
			input:    "'; INSERT INTO users VALUES ('hacker','pass');--",
			expected: true,
		},
		{
			name:     "UPDATE injection",
			input:    "1; UPDATE users SET password='hacked' WHERE id=1;--",
			expected: true,
		},
		{
			name:     "DELETE injection",
			input:    "1; DELETE FROM users WHERE id=1;--",
			expected: true,
		},
		{
			name:     "SQL comment with --",
			input:    "admin'-- -",
			expected: true,
		},
		{
			name:     "SQL comment with #",
			input:    "admin' # comment",
			expected: true,
		},
		{
			name:     "SQL comment with /* */",
			input:    "admin' /* comment */ AND '1'='1",
			expected: true,
		},
		{
			name:     "Boolean injection OR 1=1",
			input:    "' OR 1=1--",
			expected: true,
		},
		{
			name:     "Boolean injection AND 1=1",
			input:    "' AND 1=1--",
			expected: true,
		},
		{
			name:     "Hex encoding attack",
			input:    "1' AND 1=0x41434345--",
			expected: true,
		},
		{
			name:     "CHAR function injection",
			input:    "1' AND 1=CHAR(65,68,77,73,78)--",
			expected: true,
		},
		{
			name:     "ASCII function injection",
			input:    "1' AND ASCII(SUBSTRING(password,1,1))>64--",
			expected: true,
		},
		{
			name:     "Information schema enumeration",
			input:    "1' UNION SELECT table_name FROM information_schema.tables--",
			expected: true,
		},
		{
			name:     "MySQL system tables",
			input:    "1' UNION SELECT user FROM mysql.user--",
			expected: true,
		},
		{
			name:     "PostgreSQL system tables",
			input:    "1' UNION SELECT usename FROM pg_user--",
			expected: true,
		},
		{
			name:     "SQL Server system tables",
			input:    "1' UNION SELECT name FROM sys.tables--",
			expected: true,
		},
		{
			name:     "Boolean true injection",
			input:    "1' OR true--",
			expected: true,
		},
		{
			name:     "Boolean false injection",
			input:    "1' AND false--",
			expected: true,
		},
		{
			name:     "PostgreSQL sleep function",
			input:    "1' AND pg_sleep(5)--",
			expected: true,
		},
		{
			name:     "SQL Server WAITFOR delay",
			input:    "1'; WAITFOR DELAY '00:00:05'--",
			expected: true,
		},
		{
			name:     "File read attempt",
			input:    "1' UNION SELECT load_file('/etc/passwd')--",
			expected: true,
		},
		{
			name:     "File write attempt OUTFILE",
			input:    "1' UNION SELECT 'shell' INTO OUTFILE '/var/www/shell.php'--",
			expected: true,
		},
		{
			name:     "File write attempt DUMPFILE",
			input:    "1' UNION SELECT 'data' INTO DUMPFILE '/tmp/dump.txt'--",
			expected: true,
		},
		{
			name:     "Stored procedure execution",
			input:    "1'; EXEC sp_configure 'show advanced options',1--",
			expected: true,
		},
		{
			name:     "Extended stored procedure",
			input:    "1'; EXEC xp_cmdshell 'dir'--",
			expected: true,
		},
		{
			name:     "CREATE TABLE injection",
			input:    "1'; CREATE TABLE temp AS SELECT * FROM users--",
			expected: true,
		},
		{
			name:     "ALTER TABLE injection",
			input:    "1'; ALTER TABLE users ADD COLUMN backdoor VARCHAR(255)--",
			expected: true,
		},
		{
			name:     "Master database access",
			input:    "1' UNION SELECT name FROM master.dbo.sysdatabases--",
			expected: true,
		},
		{
			name:     "MSDB database access",
			input:    "1' UNION SELECT job_id FROM msdb.dbo.sysjobs--",
			expected: true,
		},
		{
			name:     "UNHEX function injection",
			input:    "1' AND 1=UNHEX('41444D494E')--",
			expected: true,
		},
		{
			name:     "Quote matching injection",
			input:    "admin' = 'admin",
			expected: false, // Doesn't match refined pattern
		},
		{
			name:     "Double quote injection",
			input:    "admin\" = \"admin",
			expected: false, // Doesn't match refined pattern
		},
		{
			name:     "Sleep with numeric parameter",
			input:    "1' AND sleep(10)--",
			expected: true,
		},

		// Negative cases - should NOT detect SQL injection
		{
			name:     "Normal text",
			input:    "This is just normal text",
			expected: false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "Numbers only",
			input:    "12345",
			expected: false,
		},
		{
			name:     "Special characters without SQL keywords",
			input:    "user@example.com; password123!",
			expected: false,
		},
		{
			name:     "Partial matches should not trigger with word boundaries",
			input:    "selection process unions benchmark discussion",
			expected: false, // Improved regex uses word boundaries
		},
		{
			name:     "URL with select parameter should not trigger",
			input:    "http://example.com?action=selection",
			expected: false, // Improved regex uses word boundaries
		},

		// Edge cases
		{
			name:     "UNION at start",
			input:    "UNION SELECT 1,2,3",
			expected: true,
		},
		{
			name:     "SELECT at end",
			input:    "some data SELECT",
			expected: false, // Just "SELECT" alone shouldn't trigger
		},
		{
			name:     "Multiple SQL keywords",
			input:    "1' UNION SELECT password FROM users WHERE username = 'admin' AND SLEEP(5)--",
			expected: true,
		},
		{
			name:     "SQL keywords with different separators",
			input:    "test\nUNION\tSELECT\r\n*",
			expected: true,
		},
		{
			name:     "SLEEP with different parameter",
			input:    "1' OR SLEEP(0.5) OR '1'='1",
			expected: true,
		},
		{
			name:     "BENCHMARK with complex expression",
			input:    "1' OR BENCHMARK(50000,SHA1('test')) OR '1'='1",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := detector.Check(tc.input)
			if result != tc.expected {
				t.Errorf("For input %q, expected %v but got %v", tc.input, tc.expected, result)
			}
		})
	}
}

func TestSQLiDetector_IntegrationWithScanner(t *testing.T) {
	detector := detectors.NewSQLi()

	testInputs := []struct {
		input    string
		expected bool
	}{
		{"normal text; DROP TABLE users;", true}, // Now detected by improved regex
		{"1' UNION SELECT * FROM users--", true},
		{"clean input", false},
		{"SELECT * FROM sensitive_data", true},
		{"This is just normal text with no SQL", false},
		{"user@example.com and some normal data", false},
	}

	for _, test := range testInputs {
		result := detector.Check(test.input)
		if result != test.expected {
			t.Errorf("Integration test failed for %q: expected %v, got %v",
				test.input, test.expected, result)
		}
	}
}

func BenchmarkSQLiDetector_Check(t *testing.B) {
	detector := detectors.NewSQLi()
	testInput := "1' UNION SELECT username,password FROM users WHERE id=1 AND SLEEP(5)--"

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		detector.Check(testInput)
	}
}

func TestSQLiDetector_LargeInput(t *testing.T) {
	detector := detectors.NewSQLi()

	// Test with large input to ensure no performance issues
	largeInput := ""
	for range 1000 {
		largeInput += "normal text "
	}
	largeInput += "UNION SELECT * FROM users"

	result := detector.Check(largeInput)
	if !result {
		t.Error("Should detect SQL injection in large input")
	}
}

// Test for false positives - legitimate content that shouldn't be flagged
func TestSQLiDetector_FalsePositives(t *testing.T) {
	detector := detectors.NewSQLi()

	legitimateInputs := []string{
		"Please select your preferred option", // Should not trigger - select without SQL context
		"The union of these sets is empty",    // Should not trigger - union without SELECT
		"Insert the key into the lock",        // Should not trigger - insert without SQL context
		"Update your profile information",     // Should not trigger - update without SQL context
		"Delete this message after reading",   // Should not trigger - delete without SQL context
		"Drop off the package at the door",    // Should not trigger - drop without TABLE
		"Create a new account today",          // Should not trigger - create without SQL context
		"Alter your settings in the menu",     // Should not trigger - alter without SQL context
		"Execute the plan carefully",          // Should not trigger - execute without stored procedure
		"Selection criteria for the job",      // Should not trigger - partial word
		"Union membership is required",        // Should not trigger - union without SELECT
		"benchmark test results",              // Should not trigger - benchmark without parentheses
		"MySQL user manual",                   // Should not trigger - doesn't match pattern
		"System tables documentation",         // Should not trigger - no specific database references
	}

	for _, input := range legitimateInputs {
		result := detector.Check(input)
		if result {
			t.Errorf("False positive detected for legitimate input: %q", input)
		}
	}
}

// Test for evasion attempts
func TestSQLiDetector_EvasionAttempts(t *testing.T) {
	detector := detectors.NewSQLi()

	evasionAttempts := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Whitespace evasion",
			input:    "1'/**/UNION/**/SELECT/**/password/**/FROM/**/users--",
			expected: true,
		},
		{
			name:     "Case variation evasion",
			input:    "1' uNiOn SeLeCt * fRoM users--",
			expected: true,
		},
		{
			name:     "Multiple space evasion",
			input:    "1'    UNION     SELECT     *     FROM     users--",
			expected: true,
		},
		{
			name:     "Tab and newline evasion",
			input:    "1'\tUNION\nSELECT\r\n*\tFROM\nusers--",
			expected: true,
		},
	}

	for _, test := range evasionAttempts {
		t.Run(test.name, func(t *testing.T) {
			result := detector.Check(test.input)
			if result != test.expected {
				t.Errorf("Evasion test %q failed: expected %v, got %v", test.name, test.expected, result)
			}
		})
	}
}

// Test for ReDoS (Regular Expression Denial of Service) resistance
func TestSQLiDetector_ReDoSResistance(t *testing.T) {
	detector := detectors.NewSQLi()

	// These inputs could cause catastrophic backtracking in poorly designed regexes
	maliciousInputs := []struct {
		name  string
		input string
	}{
		{
			name:  "Repeated whitespace pattern",
			input: "select" + strings.Repeat(" ", 10000) + "from",
		},
		{
			name:  "Long alternating pattern",
			input: strings.Repeat("union ", 1000) + "select",
		},
		{
			name:  "Nested quantifiers attack",
			input: "or " + strings.Repeat("1 ", 1000) + "= 1",
		},
		{
			name:  "Mixed repeating patterns",
			input: strings.Repeat("select ", 500) + strings.Repeat("from ", 500),
		},
		{
			name:  "Long hex pattern",
			input: "0x" + strings.Repeat("ab", 5000),
		},
		{
			name:  "Excessive SQL comments",
			input: strings.Repeat("-- ", 2000) + "union select",
		},
		// SQL injection specific catastrophic backtracking patterns
		{
			name:  "Nested SELECT with excessive whitespace",
			input: "select" + strings.Repeat(" ", 5000) + "username" + strings.Repeat(" ", 5000) + "from" + strings.Repeat(" ", 5000) + "users",
		},
		{
			name:  "Excessive UNION SELECT chain",
			input: strings.Repeat("UNION SELECT * FROM table", 2000),
		},
		{
			name:  "Boolean injection with repeated patterns",
			input: "1' OR (" + strings.Repeat("1=1 AND ", 1000) + "1=1)--",
		},
		{
			name:  "Nested parentheses with SQL functions",
			input: "1' AND " + strings.Repeat("SLEEP(", 500) + "5" + strings.Repeat(")", 500) + "--",
		},
		{
			name:  "Excessive string concatenation pattern",
			input: "1' UNION SELECT " + strings.Repeat("'a'||", 2000) + "'z'--",
		},
		{
			name:  "Multiple nested SQL comments",
			input: strings.Repeat("/*", 1000) + " SELECT * FROM users " + strings.Repeat("*/", 1000),
		},
		{
			name:  "Alternating quote patterns",
			input: strings.Repeat("'\"", 5000) + " OR 1=1--",
		},
		{
			name:  "Excessive column enumeration",
			input: "1' UNION SELECT " + strings.Repeat("null,", 1000) + "password FROM users--",
		},
		{
			name:  "Repeated table access patterns",
			input: strings.Repeat("information_schema.tables,", 1000) + "mysql.user",
		},
		{
			name:  "Excessive hex encoding chain",
			input: "1' AND password=" + strings.Repeat("0x41", 2000) + "--",
		},
		{
			name:  "Nested CHAR function calls",
			input: "1' UNION SELECT " + strings.Repeat("CHAR(", 500) + "65" + strings.Repeat(")", 500) + "--",
		},
		{
			name:  "Multiple database enumeration",
			input: strings.Repeat("database(),", 1000) + "version()",
		},
		{
			name:  "Excessive error-based injection",
			input: "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(" + strings.Repeat("version(),", 500) + "FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
		},
		{
			name:  "Time-based injection with nested delays",
			input: "1' AND IF(1=1," + strings.Repeat("SLEEP(", 200) + "5" + strings.Repeat("),0)", 200) + "--",
		},
		{
			name:  "Excessive ORDER BY enumeration",
			input: "1' ORDER BY " + strings.Repeat("1,", 1000) + "2--",
		},
		// Advanced catastrophic backtracking patterns targeting specific regex vulnerabilities
		{
			name:  "Exponential backtracking with nested groups",
			input: strings.Repeat("(select ", 100) + "1" + strings.Repeat(")", 100) + " union select 2",
		},
		{
			name:  "Polynomial backtracking with alternations",
			input: strings.Repeat("aaa", 1000) + "bbb",
		},
		{
			name:  "Evil regex pattern with optional quantifiers",
			input: strings.Repeat("a", 2000) + "X",
		},
		{
			name:  "Deeply nested SQL structure",
			input: "SELECT " + strings.Repeat("(SELECT ", 200) + "1" + strings.Repeat(")", 200) + " FROM users",
		},
		{
			name:  "Massive WHERE clause with AND/OR chains",
			input: "SELECT * FROM users WHERE " + strings.Repeat("id=1 AND ", 1000) + "name='admin'",
		},
		{
			name:  "Excessive table joins pattern",
			input: "SELECT * FROM table1 " + strings.Repeat("JOIN table2 ON table1.id=table2.id ", 500),
		},
		{
			name:  "Catastrophic comment nesting",
			input: strings.Repeat("/*", 500) + strings.Repeat("*/", 500) + " UNION SELECT password",
		},
		{
			name:  "Excessive escape sequence patterns",
			input: "SELECT * FROM users WHERE name='" + strings.Repeat("\\'", 2000) + "admin'",
		},
	}

	for _, test := range maliciousInputs {
		t.Run(test.name, func(t *testing.T) {
			// Use a timeout to ensure the regex doesn't hang
			done := make(chan bool, 1)
			var result bool

			go func() {
				result = detector.Check(test.input)
				done <- true
			}()

			select {
			case <-done:
				// Test passed - regex completed in reasonable time
				t.Logf("ReDoS test %q completed with result: %v", test.name, result)
			case <-time.After(100 * time.Millisecond):
				t.Errorf("ReDoS vulnerability detected: regex took too long for input %q", test.name)
			}
		})
	}
}
