package detectors

import "regexp"

type PathTraversalDetector struct {
	regex *regexp.Regexp
}

func NewPathTraversal() *PathTraversalDetector {
	// ReDoS-safe path traversal detection - prevents catastrophic backtracking
	// Balanced patterns to detect threats while minimizing false positives
	pattern := `(?i)` + // Case insensitive
		`(` +
		// Basic directory traversal patterns - core detection
		`\.\.[\\/]+` + `|` +
		`[\\/]\.\.[\\/]` + `|` +
		// Multiple levels of directory traversal
		`(?:\.\.[\\/]){2,8}` + `|` +
		// URL encoded traversal patterns
		`%2e%2e(?:[\\/]|%2f|%5c)` + `|` +
		`\.%2e(?:[\\/]|%2f|%5c)` + `|` +
		`%2e\.(?:[\\/]|%2f|%5c)` + `|` +
		// Double URL encoding - malicious bypass attempts
		`%252e%252e` + `|` +
		`%252f` + `|` +
		`%255c` + `|` +
		// Unicode encoding patterns
		`\\u002e\\u002e(?:[\\/]|\\u002f|\\u005c)` + `|` +
		`\\u2024\\u2024` + `|` +
		// UTF-8 overlong encoding - including incomplete sequences
		`%c0%ae%c0%ae` + `|` +
		`%e0%80%ae%e0%80%ae` + `|` +
		// Mixed encoding attempts
		`\.%c0%ae[\\/]` + `|` +
		`%c0%ae\.[\\/]` + `|` +
		// Directory traversal with null bytes
		`\.\.[\\/][^\\/]{0,50}%00` + `|` +
		`\.\.%00` + `|` +
		// Sensitive file access patterns - context-aware
		`(?:[\\/]|^|file=|path=|url=|include=|require=)etc[\\/]passwd` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)etc[\\/]shadow` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)etc[\\/]hosts` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)windows[\\/]system32` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)winnt[\\/]system32` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)boot\.ini` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)windows[\\/]win\.ini` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)proc[\\/]version` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)proc[\\/]self[\\/]environ` + `|` +
		// Home directory access patterns
		`(?:[\\/]|^|file=|path=|url=|include=|require=)home[\\/][a-zA-Z0-9_.-]{1,32}[\\/]` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)users[\\/][a-zA-Z0-9_.-]{1,32}[\\/]` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)Documents and Settings[\\/]` + `|` +
		// Application-specific sensitive directories
		`(?:[\\/]|^|file=|path=|url=|include=|require=)\.ssh[\\/]` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)\.aws[\\/]` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)\.git[\\/]` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)\.env(?:$|[^a-zA-Z0-9_])` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)config[\\/]database` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)app[\\/]config` + `|` +
		// Kubernetes and container secrets
		`(?:file=|path=|url=|include=|require=).*var[\\/]run[\\/]secrets` + `|` +
		// Log directories
		`(?:[\\/]|^|file=|path=|url=|include=|require=)var[\\/]log[\\/]` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)logs[\\/][a-zA-Z0-9_.-]{1,50}\.log` + `|` +
		// Backup and sensitive file extensions
		`[\\/](?:config|database|backup|secret|password|credential)[a-zA-Z0-9_.-]{0,20}\.(?:bak|backup|tmp|old)` + `|` +
		`[\\/](?:dump|export|data)[a-zA-Z0-9_.-]{0,20}\.sql` + `|` +
		`[\\/](?:app|database|data)[a-zA-Z0-9_.-]{0,20}\.(?:db|sqlite)` + `|` +
		// Generic file patterns that could be suspicious
		`[\\/][a-zA-Z0-9_.-]{0,30}\.(?:tmp|bak|backup)` + `|` +
		`[\\/][a-zA-Z0-9_.-]{0,30}\.(?:conf|config|ini)(?:$|[^a-zA-Z0-9_])` + `|` +
		`[\\/][a-zA-Z0-9_.-]{0,30}\.(?:sql|db|sqlite)(?:$|[^a-zA-Z0-9_])` + `|` +
		`[\\/][a-zA-Z0-9_.-]{0,30}\.(?:xml|json)(?:$|[^a-zA-Z0-9_])` + `|` +
		// Web application configuration files
		`(?:[\\/]|^|file=|path=|url=|include=|require=)web\.config` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)httpd\.conf` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)apache2\.conf` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)nginx\.conf` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)\.htaccess` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)\.htpasswd` + `|` +
		// PHP-specific attacks and bypass attempts
		`[\\/]index\.php[\\/]` + `|` +
		`php:[\\/]{2}filter` + `|` +
		`php:[\\/]{2}input` + `|` +
		`data:[\\/]{2}` + `|` +
		`file:[\\/]{2,3}` + `|` +
		`jar:file:` + `|` +
		`zip:[\\/]{2}` + `|` +
		// Path normalization bypass attempts
		`[\\/]\.[\\/]` + `|` +
		// Directory traversal in include/require statements
		`(?:include|require)(?:\s*\(|\s+).*\.\.[\\/]` + `|` +
		// JSP/Java specific directory access
		`(?:[\\/]|^|file=|path=|url=|include=|require=)WEB-INF[\\/]` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)META-INF[\\/]` + `|` +
		// Common web directories
		`(?:[\\/]|^|file=|path=|url=|include=|require=)inetpub[\\/]wwwroot` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)srv[\\/]` + `|` +
		// Container escape attempts
		`[\\/]\.\.[\\/]\.\.[\\/][a-zA-Z_]{1,20}mnt` + `|` +
		`(?:[\\/]|^|file=|path=|url=|include=|require=)proc[\\/]1[\\/]` + `|` +
		// Cloud metadata service access
		`169\.254\.169\.254` + `|` +
		// UNC path attacks - more specific to avoid matching normal backslashes
		`\\\\[a-zA-Z0-9.-]{2,}\\[a-zA-Z]+[\$\\]` + `|` +
		// Excessive directory separators (bypass attempts)
		`[\\/]{4,}` + `|` +
		// Case variation bypass for critical files
		`[Ee][Tt][Cc][\\/][Pp][Aa][Ss][Ss][Ww][Dd]` + `|` +
		// Path with wildcards in suspicious contexts - more specific
		`(?:[\\/]|file=|path=|url=|include=|require=)[a-zA-Z0-9_.-]*[\*]{1,3}` + `|` +
		// Question mark wildcards only in file context
		`(?:file=|path=|url=|include=|require=)[a-zA-Z0-9_./-]*\?{2,}` + `|` +
		// Common web server paths that shouldn't be accessible - more specific
		`(?:file=|path=|url=|include=|require=)var[\\/]www(?:$|[\\/])` + `|` +
		`(?:file=|path=|url=|include=|require=)[a-zA-Z0-9_./\\-]+var[\\/]www` +
		`)`

	return &PathTraversalDetector{
		regex: regexp.MustCompile(pattern),
	}
}

func (d *PathTraversalDetector) Name() string {
	return "path_traversal"
}

func (d *PathTraversalDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}
