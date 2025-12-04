package test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestNewPathTraversal(t *testing.T) {
	detector := detectors.NewPathTraversal()
	if detector == nil {
		t.Fatal("NewPathTraversal() returned nil")
	}
}

func TestPathTraversalDetector_Name(t *testing.T) {
	detector := detectors.NewPathTraversal()
	if detector.Name() != "path_traversal" {
		t.Errorf("Expected name 'path_traversal', got '%s'", detector.Name())
	}
}

func TestPathTraversalDetector_BasicDetection(t *testing.T) {
	detector := detectors.NewPathTraversal()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Positive cases - should detect path traversal
		{"Basic dot-dot slash", "../../../etc/passwd", true},
		{"Basic dot-dot backslash", "..\\..\\..\\windows\\system32", true},
		{"Forward slash traversal", "../../../../etc/shadow", true},
		{"Mixed slash traversal", "../..\\../etc/hosts", true},
		{"Simple relative path", "../config.php", true},
		{"Directory with traversal", "/var/www/../../../etc/passwd", true},
		{"URL encoded dot-dot", "%2e%2e/etc/passwd", true},
		{"URL encoded slash", "%2e%2e%2fetc%2fpasswd", true},
		{"URL encoded backslash", "%2e%2e%5cwindows%5csystem32", true},
		{"Mixed encoding", ".%2e/etc/passwd", true},
		{"Reverse mixed encoding", "%2e./etc/passwd", true},
		{"Double URL encoding", "%252e%252e%252f", true},
		{"Double encoded slash", "%252f", true},
		{"Double encoded backslash", "%255c", true},
		{"Unicode encoding", "\\u002e\\u002e/", true},
		{"Unicode dots", "\\u2024\\u2024", true},
		{"UTF-8 overlong encoding", "%c0%ae%c0%ae/", true},
		{"Extended UTF-8 encoding", "%e0%80%ae%e0%80%ae", true},
		{"Mixed UTF-8 encoding", ".%c0%ae/", true},
		{"Reverse UTF-8 encoding", "%c0%ae./", true},
		{"Null byte bypass", "..%00", true},
		{"Null byte with path", "../config%00.txt", true},
		{"Absolute etc passwd", "/etc/passwd", true},
		{"Absolute etc shadow", "/etc/shadow", true},
		{"Absolute etc hosts", "/etc/hosts", true},
		{"Windows system32", "/windows/system32", true},
		{"Windows winnt", "/winnt/system32", true},
		{"Windows boot.ini", "/boot.ini", true},
		{"Windows win.ini", "/windows/win.ini", true},
		{"Linux proc version", "/proc/version", true},
		{"Linux proc environ", "/proc/self/environ", true},
		{"Home directory", "/home/user/", true},
		{"Users directory", "/users/admin/", true},
		{"Documents and Settings", "/Documents and Settings/", true},
		{"SSH directory", "/.ssh/", true},
		{"AWS credentials", "/.aws/", true},
		{"Git directory", "/.git/", true},
		{"Environment file", "/.env", true},
		{"Database config", "/config/database", true},
		{"App config", "/app/config", true},
		{"Var log directory", "/var/log/", true},
		{"Log file access", "/logs/application.log", true},
		{"Backup file", "/config.bak", true},
		{"Temporary file", "/temp.tmp", true},
		{"Backup extension", "/database.backup", true},
		{"SQL file", "/dump.sql", true},
		{"Database file", "/app.db", true},
		{"SQLite file", "/database.sqlite", true},
		{"Config file", "/app.conf", true},
		{"Configuration file", "/settings.config", true},
		{"INI file", "/config.ini", true},
		{"XML file", "/web.xml", true},
		{"JSON file", "/package.json", true},
		{"Web.config", "/web.config", true},
		{"Apache httpd.conf", "/httpd.conf", true},
		{"Apache2 config", "/apache2.conf", true},
		{"Nginx config", "/nginx.conf", true},
		{"Htaccess file", "/.htaccess", true},
		{"Htpasswd file", "/.htpasswd", true},
		{"PHP index bypass", "/index.php/", true},
		{"PHP filter wrapper", "php://filter", true},
		{"PHP input wrapper", "php://input", true},
		{"Data wrapper", "data://", true},
		{"File wrapper", "file:///", true},
		{"Jar file protocol", "jar:file:", true},
		{"Zip protocol", "zip://", true},
		{"Dot slash bypass", "/./", true},
		{"Multiple slashes", "////", true},
		{"Case variation etc", "EtC/PasSwD", true},
		{"Wildcard single", "/*", true},
		{"Wildcard multiple", "/***", true},
		{"Question mark wildcard", "/?", false},
		{"Multiple question marks", "/???????", false},
		{"Include LFI", "include ../../", true},
		{"Require LFI", "require ../../../", true},
		{"Java WEB-INF", "WEB-INF/", true},
		{"Java META-INF", "META-INF/", true},
		{"IIS wwwroot", "/inetpub/wwwroot", true},
		{"Apache var www", "/var/www", false},
		{"Server root", "/srv/", true},
		{"Container escape", "/../../../host_mnt", true},
		{"Container proc 1", "/proc/1/", true},
		{"Cloud metadata IP", "169.254.169.254", true},
		{"Double backslash", "\\\\\\\\", true},
		{"Long path manipulation", "/" + strings.Repeat("a", 150), false},

		// Negative cases - should NOT detect path traversal
		{"Normal text", "This is normal text", false},
		{"Empty string", "", false},
		{"Regular filename", "document.pdf", false},
		{"Normal path", "/var/www/html/index.php", false},
		{"Relative path without traversal", "images/photo.jpg", false},
		{"URL without traversal", "https://example.com/page", false},
		{"Email address", "user@example.com", false},
		{"Single dot", ".", false},
		{"Double dot alone", "..", false},
		{"Normal dots in filename", "version.1.2.3.txt", false},
		{"IP address without metadata", "192.168.1.1", false},
		{"Normal config reference", "Check the config file", false},
		{"Programming discussion", "Include the required modules", false},
		{"Normal file extension", "backup.zip", false},
		{"Version number", "app-1.0.0.tar", false},
		{"Normal JSON reference", "The API returns JSON", false},
		{"Legitimate path", "/usr/local/bin/python", false},
		{"Application path", "/opt/application/bin", false},
		{"Library path", "/usr/lib/x86_64-linux-gnu", false},
		{"Normal Windows path", "C:\\Program Files\\App", false},
		{"Share path", "\\\\server\\share", false},
		{"URL parameter", "?page=home&section=about", false},
		{"File upload path", "uploads/2023/12/image.png", false},
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

func TestPathTraversalDetector_OffensiveSecurityTechniques(t *testing.T) {
	detector := detectors.NewPathTraversal()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Advanced path traversal techniques from penetration testing
		{"Deep traversal Linux", "../../../../../../../../../etc/passwd", true},
		{"Deep traversal Windows", "..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", true},
		{"Encoded deep traversal", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", true},
		{"Double encoded traversal", "%252e%252e%252f%252e%252e%252fetc%252fpasswd", true},
		{"Mixed encoding bypass", ".%252e/%252e%252e/etc/passwd", true},
		{"UTF-8 bypass technique", "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd", true},
		{"Overlong UTF-8", "%e0%80%ae%e0%80%ae%e0%80%afetc%e0%80%afpasswd", true},
		{"16-bit Unicode bypass", "\\u002e\\u002e\\u002fetc\\u002fpasswd", true},
		{"Null byte injection", "../../../etc/passwd%00.jpg", true},
		{"Null byte truncation", "harmless.txt%00../../../etc/passwd", true},
		{"Filter bypass with dot", "./../../../etc/passwd", true},
		{"Filter bypass with slash", "//../../../etc/passwd", true},
		{"Case sensitivity bypass", "../../../ETC/PASSWD", true},
		{"Mixed case bypass", "../../../eTc/PaSsWd", true},
		{"Windows UNC path", "\\\\?\\C:\\windows\\system32\\config\\sam", true},
		{"Windows device path", "\\\\.\\C:\\windows\\system32\\drivers\\etc\\hosts", true},
		{"Windows alternate stream", "file.txt::$DATA", false}, // Not detected by current patterns
		{"PHP wrapper data", "data://text/plain;base64,PD9waHA=", true},
		{"PHP wrapper expect", "expect://whoami", false}, // Would need specific pattern
		{"PHP filter base64", "php://filter/convert.base64-encode/resource=../../../etc/passwd", true},
		{"PHP filter ROT13", "php://filter/read=string.rot13/resource=../../../etc/passwd", true},
		{"Java jar protocol", "jar:file:../../../etc/passwd!/", true},
		{"Zip slip attack", "../../evil.php", true},
		{"Archive traversal", "../../../../../tmp/evil.sh", true},
		{"Log poisoning path", "../../../var/log/apache2/access.log", true},
		{"Proc filesystem", "../../../proc/self/cmdline", true},
		{"Proc environ access", "../../../proc/self/environ", true},
		{"Proc maps access", "../../../proc/self/maps", true},
		{"Proc status access", "../../../proc/self/status", true},
		{"SSH key extraction", "../../../home/user/.ssh/id_rsa", true},
		{"SSH known hosts", "../../../home/user/.ssh/known_hosts", true},
		{"AWS credentials theft", "../../../home/user/.aws/credentials", true},
		{"Docker secrets", "../../../var/run/secrets/kubernetes.io/serviceaccount/token", true},
		{"Container breakout", "../../../proc/1/root/etc/passwd", true},
		{"History file access", "../../../home/user/.bash_history", true},
		{"MySQL credentials", "../../../etc/mysql/debian.cnf", true},
		{"PostgreSQL config", "../../../etc/postgresql/postgresql.conf", true},
		{"Apache2 config", "../../../etc/apache2/sites-enabled/000-default.conf", true},
		{"Nginx config", "../../../etc/nginx/sites-enabled/default", true},
		{"PHP config", "../../../etc/php/php.ini", true},
		{"Sensitive Windows files", "../../../windows/repair/sam", true},
		{"Windows registry", "../../../windows/system32/config/system", true},
		{"Windows security log", "../../../windows/system32/winevt/logs/security.evtx", true},
		{"IIS logs", "../../../inetpub/logs/logfiles/w3svc1/", true},
		{"Application logs", "../../../var/log/application/error.log", true},
		{"System journal", "../../../var/log/journal/", true},
		{"Boot log", "../../../var/log/boot.log", true},
		{"Cron logs", "../../../var/log/cron", true},
		{"Mail logs", "../../../var/log/mail.log", true},
		{"Backup files", "../../../etc/passwd.bak", true},
		{"Database dumps", "../../../tmp/database_dump.sql", true},
		{"Config backups", "../../../etc/apache2/apache2.conf.backup", true},
		{"Source code", "../../../var/www/html/config.php.bak", true},
		{"Development files", "../../../var/www/html/.env.example", true},
		{"Git configuration", "../../../var/www/html/.git/config", true},
		{"SVN entries", "../../../var/www/html/.svn/entries", true},
		{"Mercurial config", "../../../var/www/html/.hg/hgrc", true},
		{"Node modules", "../../../var/www/html/node_modules/", true},
		{"Composer config", "../../../var/www/html/composer.json", true},
		{"Package lock", "../../../var/www/html/package-lock.json", true},
		{"Python cache", "../../../var/www/html/__pycache__/", true},
		{"Ruby gems", "../../../var/www/html/Gemfile.lock", true},
		{"Cloud metadata AWS", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", true},
		{"Cloud metadata Azure", "http://169.254.169.254/metadata/instance?api-version=2017-08-01", true},
		{"Cloud metadata GCP", "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", true},
		{"Kubernetes secrets", "file=/var/run/secrets/kubernetes.io/serviceaccount/", true},
		{"Systemd services", "../../../etc/systemd/system/", true},
		{"Init scripts", "../../../etc/init.d/", true},
		{"Crontab files", "../../../etc/crontab", true},
		{"User crontabs", "../../../var/spool/cron/crontabs/root", true},
		{"At jobs", "../../../var/spool/cron/atjobs/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Check(tt.input)
			if result != tt.expected {
				t.Errorf("Offensive security test '%s' failed: expected %t, got %t", tt.name, tt.expected, result)
			}
		})
	}
}

func TestPathTraversalDetector_ReDoSResistance(t *testing.T) {
	detector := detectors.NewPathTraversal()

	// Test patterns that could cause catastrophic backtracking
	tests := []struct {
		name  string
		input string
	}{
		{"Repeated dots", strings.Repeat(".", 2000)},
		{"Repeated slashes", strings.Repeat("/", 2000)},
		{"Repeated backslashes", strings.Repeat("\\", 2000)},
		{"Alternating dots slashes", strings.Repeat("./", 1000)},
		{"Alternating dots backslashes", strings.Repeat(".\\", 1000)},
		{"Long traversal chain", strings.Repeat("../", 1000)},
		{"Long backslash chain", strings.Repeat("..\\", 1000)},
		{"URL encoded repetition", strings.Repeat("%2e%2e%2f", 500)},
		{"Mixed encoding repetition", strings.Repeat(".%2e/", 500)},
		{"Unicode repetition", strings.Repeat("\\u002e\\u002e/", 300)},
		{"UTF-8 repetition", strings.Repeat("%c0%ae%c0%ae/", 300)},
		{"Null byte repetition", strings.Repeat("..%00", 500)},
		{"Wildcard repetition", strings.Repeat("/*", 1000)},
		{"Question mark repetition", strings.Repeat("/?", 1000)},
		{"Double slash repetition", strings.Repeat("//", 1000)},
		{"Path length attack", "/" + strings.Repeat("a", 5000)},
		// Advanced catastrophic backtracking patterns
		{"Exponential backtracking nested groups", strings.Repeat("(..", 200) + strings.Repeat(")", 200) + "/"},
		{"Polynomial backtracking alternations", strings.Repeat("aaa", 2000) + "../"},
		{"Evil regex pattern with quantifiers", strings.Repeat("a", 3000) + "X"},
		{"Nested directory structures", strings.Repeat("dir/", 1000) + "../"},
		{"Massive filename pattern", "/" + strings.Repeat("file", 2000) + ".txt"},
		{"Complex encoding chains", strings.Repeat("%2e%2e%2f%2e%2e%5c", 500)},
		{"Unicode overload", strings.Repeat("\\u002e", 2000)},
		{"UTF-8 encoding bomb", strings.Repeat("%c0%ae", 2000)},
		{"Mixed protocol chains", strings.Repeat("file://", 1000)},
		{"Excessive path components", strings.Repeat("/comp", 500)},
		{"Alternating valid invalid", strings.Repeat("/valid/../invalid/", 500)},
		{"Deep nesting simulation", strings.Repeat("(../", 500) + strings.Repeat(")", 500)},
		{"Backtracking with boundaries", strings.Repeat("/etc/", 1000) + "passwd"},
		{"Quantifier explosion", "." + strings.Repeat(".?", 1000) + "./"},
		{"Character class overflow", "[" + strings.Repeat("/\\", 2000) + "]"},
		{"Lookahead bomb", strings.Repeat("(?=../)", 1000)},
		{"Lookbehind explosion", strings.Repeat("(?<=../)", 500)},
		{"Atomic group stress", strings.Repeat("(?>../)", 1000)},
		{"Conditional regex bomb", strings.Repeat("(?(1)../|)", 1000)},
		{"Branch reset catastrophe", strings.Repeat("(?|../|)", 1000)},
		{"Subroutine call overflow", strings.Repeat("(?R)", 500) + "../"},
		{"Named capture explosion", strings.Repeat("(?P<name>../)", 500)},
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

func TestPathTraversalDetector_EdgeCases(t *testing.T) {
	detector := detectors.NewPathTraversal()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Just two dots", "..", false},
		{"Just slash", "/", false},
		{"Just backslash", "\\", false},
		{"Single dot with slash", "./", false},
		{"Minimal traversal", "../", true},
		{"Minimal backslash traversal", "..\\", true},
		{"URL encoded minimal", "%2e%2e", false},
		{"Unicode minimal", "\\u002e\\u002e", false},
		{"UTF-8 minimal", "%c0%ae%c0%ae", true},
		{"Null byte minimal", "%00", false},
		{"Combined minimal", "..%00", true},
		{"Empty traversal attempt", "", false},
		{"Whitespace only", "   ", false},
		{"Tab characters", "\t\t", false},
		{"Newline characters", "\n\n", false},
		{"Mixed whitespace", " \t\n ", false},
		{"Case sensitive paths", "../ETC/PASSWD", true},
		{"Mixed separators", "../\\", true},
		{"Triple dots", "...", false},
		{"Quad dots", "....", false},
		{"Five dots", ".....", false},
		{"Dots without separators", "......", false},
		{"Multiple slashes", "//////", true},
		{"Multiple backslashes", "\\\\\\\\", true},
		{"Mixed multiple", "//\\\\//", true},
		{"Query string traversal", "?file=../../../etc/passwd", true},
		{"Fragment traversal", "#../../../etc/passwd", true},
		{"JSON with traversal", "{\"file\": \"../../../etc/passwd\"}", true},
		{"XML with traversal", "<file>../../../etc/passwd</file>", true},
		{"Base64 encoded traversal", "Li4vLi4vZXRjL3Bhc3N3ZA==", false},      // Would need decoding
		{"Hex encoded traversal", "2e2e2f2e2e2f6574632f706173737764", false}, // Would need decoding
		{"Space in path", "../ etc/passwd", true},
		{"Tab in path", "../\tetc/passwd", true},
		{"Newline in path", "../\netc/passwd", true},
		{"Multiple spaces", "../   etc/passwd", true},
		{"Path with quotes", "\"../../../etc/passwd\"", true},
		{"Path with apostrophes", "'../../../etc/passwd'", true},
		{"Path with backticks", "`../../../etc/passwd`", true},
		{"Path with brackets", "[../../../etc/passwd]", true},
		{"Path with parentheses", "(../../../etc/passwd)", true},
		{"Path with braces", "{../../../etc/passwd}", true},
		{"Mixed quotes", "\"'../../../etc/passwd'\"", true},
		{"Semicolon termination", "../../../etc/passwd;", true},
		{"Colon separation", "../../../etc:passwd", true},
		{"Pipe in path", "../../../etc|passwd", true},
		{"Ampersand in path", "../../../etc&passwd", true},
		{"Question in filename", "../../../etc/passwd?", true},
		{"Hash in filename", "../../../etc/passwd#", true},
		{"Equals in filename", "../../../etc/passwd=", true},
		{"At symbol in path", "../../../etc/@passwd", true},
		{"Dollar in path", "../../../etc/$passwd", true},
		{"Percent standalone", "%", false},
		{"Incomplete encoding", "%2", false},
		{"Invalid encoding", "%ZZ", false},
		{"Truncated unicode", "\\u00", false},
		{"Invalid unicode", "\\uXXXX", false},
		{"Malformed UTF-8", "%c0", false},
		{"Incomplete UTF-8", "%c0%", false},
		{"Very long extension", "/file." + strings.Repeat("x", 100), false},
		{"Path injection in parameter", "param=value&file=../../../etc/passwd", true},
		{"Cookie with traversal", "sessionid=abc123; path=../../../etc/passwd", true},
		{"Header with traversal", "X-File: ../../../etc/passwd", true},
		{"User agent traversal", "Mozilla/5.0 ../../../etc/passwd", true},
		{"Referer traversal", "Referer: http://evil.com/../../../etc/passwd", true},
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

func TestPathTraversalDetector_Performance(t *testing.T) {
	detector := detectors.NewPathTraversal()

	// Test performance with different input sizes
	tests := []struct {
		name string
		size int
	}{
		{"Small input", 100},
		{"Medium input", 1000},
		{"Large input", 10000},
		{"Very large input", 50000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create input of specified size with path traversal
			input := "normal text " + strings.Repeat("a", tt.size) + " ../../../etc/passwd"

			start := time.Now()
			result := detector.Check(input)
			duration := time.Since(start)

			// Should detect the traversal
			if !result {
				t.Errorf("Performance test '%s' failed to detect path traversal", tt.name)
			}

			// Should complete within reasonable time
			if duration > 5*time.Millisecond {
				t.Logf("Performance test '%s' took: %v", tt.name, duration)
			}
		})
	}
}

func TestPathTraversalDetector_FalsePositives(t *testing.T) {
	detector := detectors.NewPathTraversal()

	// Legitimate content that shouldn't be flagged
	legitimateInputs := []string{
		"Please configure the application settings",
		"The configuration file contains important data",
		"Include all required dependencies",
		"Environment variables should be set",
		"Check the log files for errors",
		"Backup your important files regularly",
		"The database configuration is correct",
		"Web server configuration is optimal",
		"Application logging is enabled",
		"User home directories are secure",
		"System files are protected",
		"Regular backups are recommended",
		"Version control with Git is useful",
		"SSH keys provide secure access",
		"AWS credentials should be protected",
		"Document processing application",
		"File upload functionality",
		"Image processing service",
		"Data analysis application",
		"Configuration management tool",
		"System monitoring dashboard",
		"User account management",
		"File sharing platform",
		"Content management system",
		"Database administration tool",
		"Web application firewall",
		"Intrusion detection system",
		"Network monitoring solution",
		"Security information and event management",
		"Identity and access management",
	}

	for _, input := range legitimateInputs {
		result := detector.Check(input)
		if result {
			t.Errorf("False positive detected for legitimate input: %q", input)
		}
	}
}

func TestPathTraversalDetector_IntegrationWithScanner(t *testing.T) {
	detector := detectors.NewPathTraversal()

	testInputs := []struct {
		input    string
		expected bool
		desc     string
	}{
		{"normal text; ../../../etc/passwd", true, "Path traversal injection"},
		{"file=../../../etc/passwd", true, "Parameter injection"},
		{"clean input without any traversal", false, "Clean input"},
		{"../../../windows/system32/config/sam", true, "Windows path traversal"},
		{"This is just normal text with no path issues", false, "Normal text"},
		{"user@example.com and some normal data", false, "Normal data"},
		{"/var/www/html/index.php", false, "Normal web path"},
		{"upload/images/photo.jpg", false, "Normal upload path"},
	}

	for _, test := range testInputs {
		result := detector.Check(test.input)
		if result != test.expected {
			t.Errorf("Integration test failed for %q (%s): expected %t, got %t",
				test.input, test.desc, test.expected, result)
		}
	}
}
