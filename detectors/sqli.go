package detectors

import "regexp"

type SQLiDetector struct {
	regex *regexp.Regexp
}

func NewSQLi() *SQLiDetector {
	// ReDoS-safe SQL injection detection - prevents catastrophic backtracking
	pattern := `(?i)` + // Case insensitive
		`(` +
		// UNION-based injections (most common) - atomic groups to prevent backtracking
		`\bunion(?:\s+all)?\s+select\b` + `|` +
		// SELECT with FROM (injection context) - limited quantifiers
		`\bselect(?:\s+[^\s]{1,50}){1,10}\s+from\s+[a-zA-Z_][a-zA-Z0-9_]{0,63}` + `|` +
		// INSERT/UPDATE/DELETE with injection context - specific patterns
		`\binsert\s+into\s+[a-zA-Z_][a-zA-Z0-9_]{0,63}` + `|` +
		`\bupdate\s+[a-zA-Z_][a-zA-Z0-9_]{0,63}\s+set\s+[a-zA-Z_]` + `|` +
		`\bdelete\s+from\s+[a-zA-Z_][a-zA-Z0-9_]{0,63}` + `|` +
		// DROP/CREATE/ALTER with dangerous context - bounded
		`\bdrop\s+(?:table|database)\s+[a-zA-Z_][a-zA-Z0-9_]{0,63}` + `|` +
		`\bcreate\s+(?:table|database)\s+[a-zA-Z_][a-zA-Z0-9_]{0,63}` + `|` +
		`\balter\s+table\s+[a-zA-Z_][a-zA-Z0-9_]{0,63}` + `|` +
		// Dangerous functions with parentheses - atomic
		`\b(?:sleep|benchmark|load_file|pg_sleep|waitfor)\s*\(` + `|` +
		// SQL comments (injection indicators) - simple alternation
		`(?:--|#|/\*|\*/)` + `|` +
		// Boolean-based injections - bounded quantifiers
		`\bor\s+[0-9]{1,10}\s*=\s*[0-9]{1,10}\b` + `|` +
		`\band\s+[0-9]{1,10}\s*=\s*[0-9]{1,10}\b` + `|` +
		`\bor\s+(?:true|false)\b` + `|` +
		`\band\s+(?:true|false)\b` + `|` +
		// Hex encoding (common in injections) - bounded
		`\b0x[0-9a-f]{2,16}\b` + `|` +
		// Char/ASCII functions (encoding attempts) - atomic
		`\b(?:char|ascii|unhex)\s*\(` + `|` +
		// System table access - specific patterns
		`\binformation_schema\.` + `|` +
		`\bmysql\.user\b` + `|` +
		`\bpg_(?:user|tables)\b` + `|` +
		`\bsys\.(?:tables|databases)\b` + `|` +
		`\bmaster\.(?:dbo|sys)\.` + `|` +
		`\bmsdb\.` + `|` +
		// File operations (dangerous) - atomic groups
		`\binto\s+(?:outfile|dumpfile)\s*['"/]` + `|` +
		// Stored procedure execution - atomic
		`\b(?:exec|execute)\s+(?:sp_|xp_)[a-zA-Z_]` +
		`)`

	return &SQLiDetector{
		regex: regexp.MustCompile(pattern),
	}
}

func (d *SQLiDetector) Name() string {
	return "sql_injection"
}

func (d *SQLiDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}
