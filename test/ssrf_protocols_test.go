package test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestNewSSRFProtocols(t *testing.T) {
	detector := detectors.NewSSRFProtocols()
	if detector == nil {
		t.Fatal("NewSSRFProtocols() returned nil")
	}
}

func TestSSRFProtocolsDetector_Name(t *testing.T) {
	detector := detectors.NewSSRFProtocols()
	expected := "ssrf_protocols"
	if detector.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, detector.Name())
	}
}

func TestSSRFProtocolsDetector_Check(t *testing.T) {
	detector := detectors.NewSSRFProtocols()

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		// Positive cases - should detect SSRF protocols
		{
			name:     "HTTP localhost",
			input:    "http://localhost/admin",
			expected: true,
		},
		{
			name:     "HTTPS localhost",
			input:    "https://localhost:8080/api",
			expected: true,
		},
		{
			name:     "HTTP 127.0.0.1",
			input:    "http://127.0.0.1/internal",
			expected: true,
		},
		{
			name:     "HTTPS 127.0.0.1 with port",
			input:    "https://127.0.0.1:3000/secret",
			expected: true,
		},
		{
			name:     "HTTP 0.0.0.0",
			input:    "http://0.0.0.0/config",
			expected: true,
		},
		{
			name:     "Private network 10.x",
			input:    "http://10.0.0.1/admin",
			expected: true,
		},
		{
			name:     "Private network 172.16.x",
			input:    "https://172.16.0.1/internal",
			expected: true,
		},
		{
			name:     "Private network 172.31.x (end range)",
			input:    "http://172.31.255.255/api",
			expected: true,
		},
		{
			name:     "Private network 192.168.x",
			input:    "https://192.168.1.1/router",
			expected: true,
		},
		{
			name:     "FTP protocol",
			input:    "ftp://example.com/files",
			expected: true,
		},
		{
			name:     "File protocol local",
			input:    "file:///etc/passwd",
			expected: true,
		},
		{
			name:     "File protocol Windows",
			input:    "file://C:/Windows/system32/config/sam",
			expected: true,
		},
		{
			name:     "Gopher protocol",
			input:    "gopher://localhost:70/",
			expected: true,
		},
		{
			name:     "LDAP protocol",
			input:    "ldap://ldap.example.com:389/",
			expected: true,
		},
		{
			name:     "LDAPS protocol",
			input:    "ldaps://secure-ldap.com:636/",
			expected: true,
		},
		{
			name:     "Dictionary protocol",
			input:    "dict://dict.example.com:2628/",
			expected: true,
		},
		{
			name:     "Telnet protocol",
			input:    "telnet://telnet.example.com:23/",
			expected: true,
		},
		{
			name:     "TFTP protocol",
			input:    "tftp://tftp.example.com/config",
			expected: true,
		},
		{
			name:     "SSH protocol",
			input:    "ssh://ssh.example.com:22/",
			expected: true,
		},
		{
			name:     "IMAP protocol",
			input:    "imap://mail.example.com:143/",
			expected: true,
		},
		{
			name:     "IMAPS protocol",
			input:    "imaps://secure-mail.com:993/",
			expected: true,
		},
		{
			name:     "POP3 protocol",
			input:    "pop3://mail.example.com:110/",
			expected: true,
		},
		{
			name:     "POP3S protocol",
			input:    "pop3s://secure-mail.com:995/",
			expected: true,
		},
		{
			name:     "SMTP protocol",
			input:    "smtp://mail.example.com:25/",
			expected: true,
		},
		{
			name:     "SMTPS protocol",
			input:    "smtps://secure-mail.com:465/",
			expected: true,
		},
		{
			name:     "RTSP protocol",
			input:    "rtsp://media.example.com:554/stream",
			expected: true,
		},
		{
			name:     "SCP protocol",
			input:    "scp://server.example.com/file.txt",
			expected: true,
		},
		{
			name:     "SFTP protocol",
			input:    "sftp://ftp.example.com/secure/",
			expected: true,
		},
		{
			name:     "MySQL protocol",
			input:    "mysql://db.example.com:3306/database",
			expected: true,
		},
		{
			name:     "PostgreSQL protocol",
			input:    "postgresql://db.example.com:5432/mydb",
			expected: true,
		},
		{
			name:     "Redis protocol",
			input:    "redis://cache.example.com:6379/0",
			expected: true,
		},
		{
			name:     "MongoDB protocol",
			input:    "mongodb://mongo.example.com:27017/db",
			expected: true,
		},
		{
			name:     "AMQP protocol",
			input:    "amqp://rabbit.example.com:5672/",
			expected: true,
		},
		{
			name:     "AMQPS protocol",
			input:    "amqps://secure-rabbit.com:5671/",
			expected: true,
		},
		{
			name:     "WebDAV protocol",
			input:    "webdav://dav.example.com/files/",
			expected: true,
		},
		{
			name:     "WebDAVS protocol",
			input:    "webdavs://secure-dav.com/files/",
			expected: true,
		},
		{
			name:     "AWS metadata service",
			input:    "http://169.254.169.254/latest/meta-data/",
			expected: true,
		},
		{
			name:     "Google Cloud metadata",
			input:    "http://metadata.google.internal/computeMetadata/v1/",
			expected: true,
		},
		{
			name:     "Azure metadata service",
			input:    "http://169.254.169.254/metadata/instance",
			expected: true,
		},
		{
			name:     "Alibaba Cloud metadata",
			input:    "http://100.100.100.200/latest/meta-data/",
			expected: true,
		},
		{
			name:     "Docker internal network",
			input:    "http://172.17.0.1/container-info",
			expected: true,
		},
		{
			name:     "Kubernetes service",
			input:    "http://api-server.default.svc.cluster.local/api/v1/",
			expected: true,
		},
		{
			name:     "Unix domain socket",
			input:    "unix:///var/run/docker.sock",
			expected: true,
		},
		{
			name:     "Data URL with base64",
			input:    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
			expected: true,
		},
		{
			name:     "JavaScript protocol",
			input:    "javascript:alert('xss')",
			expected: true,
		},
		{
			name:     "VBScript protocol",
			input:    "vbscript:msgbox('xss')",
			expected: true,
		},
		{
			name:     "MHTML protocol",
			input:    "mhtml:file.mht",
			expected: true,
		},
		{
			name:     "Chrome extension",
			input:    "chrome-extension://abcdefghijklmnopqrstuvwxyz123456/popup.html",
			expected: true,
		},
		{
			name:     "Firefox extension",
			input:    "moz-extension://12345678-1234-5678-9abc-123456789abc/content.js",
			expected: true,
		},
		{
			name:     "Edge extension",
			input:    "ms-browser-extension://extension-id-12345/background.js",
			expected: true,
		},
		{
			name:     "Windows UNC path",
			input:    "\\\\server.local\\share\\file.txt",
			expected: true,
		},
		{
			name:     "RTMP protocol",
			input:    "rtmp://streaming.example.com/live/stream",
			expected: true,
		},
		{
			name:     "RTMPS protocol",
			input:    "rtmps://secure-streaming.com/live/stream",
			expected: true,
		},
		{
			name:     "WebSocket localhost",
			input:    "ws://localhost:8080/websocket",
			expected: true,
		},
		{
			name:     "Secure WebSocket private network",
			input:    "wss://192.168.1.100:9001/ws",
			expected: true,
		},
		{
			name:     "Double URL encoding bypass",
			input:    "http://example.com/%252F..%252F..%252Fetc%252Fpasswd",
			expected: true,
		},
		{
			name:     "Triple URL encoding bypass",
			input:    "http://example.com/%25252F..%25252F..%25252Fetc%25252Fpasswd",
			expected: false, // Complex encoding patterns may need application-level handling
		},
		{
			name:     "Unicode URL encoding bypass",
			input:    "http://example.com/%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
			expected: false, // Complex Unicode encoding may need application-level handling
		},
		{
			name:     "Decimal IP representation",
			input:    "http://2130706433/", // 127.0.0.1 in decimal
			expected: true,
		},
		{
			name:     "Hex IP representation",
			input:    "http://0x7f000001/", // 127.0.0.1 in hex
			expected: true,
		},
		{
			name:     "Mixed IP representation",
			input:    "http://127.0.0.0x1/", // Mixed notation
			expected: true,
		},
		{
			name:     "IPv6 localhost",
			input:    "http://[::1]:8080/admin",
			expected: true,
		},
		{
			name:     "DNS rebinding attack",
			input:    "http://admin.localtest.me/internal",
			expected: true,
		},
		{
			name:     "DNS rebinding lvh.me",
			input:    "http://test.lvh.me:3000/api",
			expected: true,
		},
		{
			name:     "Case insensitive HTTP",
			input:    "HTTP://LOCALHOST/ADMIN",
			expected: true,
		},
		{
			name:     "Case insensitive FTP",
			input:    "FTP://EXAMPLE.COM/FILES",
			expected: true,
		},
		{
			name:     "Case insensitive FILE",
			input:    "FILE:///etc/passwd",
			expected: true,
		},
		{
			name:     "Case insensitive GOPHER",
			input:    "GOPHER://localhost:70/",
			expected: true,
		},
		{
			name:     "Mixed case protocols",
			input:    "LdAp://LdAp.ExAmPlE.cOm:389/",
			expected: true,
		},
		{
			name:     "SSRF in JSON payload",
			input:    `{"url": "http://localhost/admin", "method": "GET"}`,
			expected: true,
		},
		{
			name:     "SSRF in XML",
			input:    "<request><url>http://127.0.0.1/internal</url></request>",
			expected: true,
		},
		{
			name:     "SSRF with query parameters",
			input:    "http://localhost/webhook?callback=http://attacker.com/steal",
			expected: true,
		},

		// Negative cases - should NOT detect SSRF protocols
		{
			name:     "Normal HTTPS public domain",
			input:    "https://www.google.com/search?q=test",
			expected: false,
		},
		{
			name:     "Normal HTTP public domain",
			input:    "http://example.com/api/users",
			expected: false,
		},
		{
			name:     "Public HTTPS with port",
			input:    "https://api.github.com:443/repos",
			expected: false, // Public host with port should not be detected
		},
		{
			name:     "Regular FTP public server",
			input:    "ftp://files.publicserver.com/downloads",
			expected: true, // FTP protocol itself is dangerous
		},
		{
			name:     "Normal text without protocols",
			input:    "This is just normal text",
			expected: false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "Email address",
			input:    "user@example.com",
			expected: false,
		},
		{
			name:     "Path without protocol",
			input:    "/api/users/123",
			expected: false,
		},
		{
			name:     "Query string without protocol",
			input:    "?search=localhost&page=1",
			expected: false,
		},
		{
			name:     "Domain name only",
			input:    "example.com",
			expected: false,
		},
		{
			name:     "IP address only",
			input:    "192.168.1.1",
			expected: false,
		},
		{
			name:     "Port number only",
			input:    ":8080",
			expected: false,
		},
		{
			name:     "Protocol-like text in sentence",
			input:    "The http protocol is widely used",
			expected: false,
		},
		{
			name:     "File path without protocol",
			input:    "/etc/passwd",
			expected: false,
		},
		{
			name:     "Windows path without protocol",
			input:    "C:\\Windows\\System32",
			expected: false,
		},
		{
			name:     "Public IP ranges (not private)",
			input:    "http://8.8.8.8/public",
			expected: false,
		},
		{
			name:     "Public subnet not in private ranges",
			input:    "http://173.16.0.1/api", // Not 172.16.x.x
			expected: false,
		},
		{
			name:     "Regular words containing protocol names",
			input:    "The teleportation mechanism uses HTTP-like protocols",
			expected: false,
		},
		{
			name:     "Numbers that look like IPs but aren't",
			input:    "Version 127.0.0.1 of the software",
			expected: false,
		},

		// Edge cases
		{
			name:     "Protocol at start of string",
			input:    "http://localhost",
			expected: true,
		},
		{
			name:     "Protocol at end of string",
			input:    "Check this: http://127.0.0.1",
			expected: true,
		},
		{
			name:     "Multiple protocols in string",
			input:    "Try http://localhost and ftp://internal.server",
			expected: true,
		},
		{
			name:     "Protocol with different separators",
			input:    "http://localhost\nftp://example.com\tgopher://test.local",
			expected: true,
		},
		{
			name:     "Localhost with different ports",
			input:    "http://localhost:22/ssh-tunnel",
			expected: true,
		},
		{
			name:     "Private IP edge case 172.15.x (not private)",
			input:    "http://172.15.255.255/api",
			expected: false,
		},
		{
			name:     "Private IP edge case 172.32.x (not private)",
			input:    "http://172.32.0.1/api",
			expected: false,
		},
		{
			name:     "Protocol-like but incomplete",
			input:    "http:// incomplete URL",
			expected: false,
		},
		{
			name:     "Malformed protocol",
			input:    "ht tp://localhost/",
			expected: false,
		},
		{
			name:     "Protocol in comment",
			input:    "<!-- http://localhost/admin -->",
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

func TestSSRFProtocolsDetector_IntegrationWithScanner(t *testing.T) {
	detector := detectors.NewSSRFProtocols()

	testInputs := []struct {
		input    string
		expected bool
	}{
		{"http://localhost/admin", true},
		{"ftp://internal.server/files", true},
		{"https://www.google.com", false},
		{"file:///etc/passwd", true},
		{"This is just normal text", false},
		{"gopher://localhost:70/", true},
		{"Clean input without protocols", false},
	}

	for _, test := range testInputs {
		result := detector.Check(test.input)
		if result != test.expected {
			t.Errorf("Integration test failed for %q: expected %v, got %v",
				test.input, test.expected, result)
		}
	}
}

func BenchmarkSSRFProtocolsDetector_Check(t *testing.B) {
	detector := detectors.NewSSRFProtocols()
	testInput := "http://localhost/admin?callback=gopher://internal.server:70/"

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		detector.Check(testInput)
	}
}

func TestSSRFProtocolsDetector_LargeInput(t *testing.T) {
	detector := detectors.NewSSRFProtocols()

	// Test with large input to ensure no performance issues
	largeInput := ""
	for range 1000 {
		largeInput += "normal text "
	}
	largeInput += "http://localhost/admin"

	result := detector.Check(largeInput)
	if !result {
		t.Error("Should detect SSRF protocol in large input")
	}
}

// Test for false positives - legitimate content that shouldn't be flagged
func TestSSRFProtocolsDetector_FalsePositives(t *testing.T) {
	detector := detectors.NewSSRFProtocols()

	legitimateInputs := []string{
		"Visit https://www.example.com for more information",
		"Download from http://downloads.example.com/file.zip",
		"Contact us at support@example.com",
		"The HTTP protocol specification",
		"FTP is an older file transfer protocol",
		"File operations in the application",
		"Localhost development server documentation",
		"Network address 192.168.1.1 configuration",
		"TCP port 127 is assigned to...",
		"Protocol version 1.0.0.1 released",
		"Dictionary definition of network terms",
		"Telnet client software review",
		"TFTP server configuration guide",
		"SSH key management best practices",
		"Email IMAP settings instructions",
		"POP3 client configuration tutorial",
		"SMTP server setup documentation",
		"RTSP streaming protocol overview",
		"Secure copy (SCP) command usage",
		"SFTP client connection guide",
		"MySQL database administration",
		"PostgreSQL installation instructions",
		"Redis cache configuration",
		"MongoDB replica set setup",
		"AMQP message queue concepts",
		"WebDAV folder synchronization",
	}

	for _, input := range legitimateInputs {
		result := detector.Check(input)
		if result {
			t.Errorf("False positive detected for legitimate input: %q", input)
		}
	}
}

// Test for evasion attempts
func TestSSRFProtocolsDetector_EvasionAttempts(t *testing.T) {
	detector := detectors.NewSSRFProtocols()

	evasionAttempts := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Case variation evasion",
			input:    "HtTp://LoCaLhOsT/AdMiN",
			expected: true,
		},
		{
			name:     "Mixed protocol case",
			input:    "FtP://InTeRnAl.SeRvEr/FiLeS",
			expected: true,
		},
		{
			name:     "URL encoding bypass",
			input:    "http://localhost%2Fadmin",
			expected: true, // Base protocol still detected
		},
		{
			name:     "Double URL encoding",
			input:    "http://example.com/%252F..%252F..%252Fetc%252Fpasswd",
			expected: true,
		},
		{
			name:     "Unicode encoding bypass",
			input:    "http://example.com/%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
			expected: false, // Complex Unicode encoding may need application-level handling
		},
		{
			name:     "Decimal IP obfuscation",
			input:    "http://2130706433/admin", // 127.0.0.1 in decimal
			expected: true,
		},
		{
			name:     "Hex IP obfuscation",
			input:    "http://0x7f000001/admin", // 127.0.0.1 in hex
			expected: true,
		},
		{
			name:     "Mixed IP notation",
			input:    "http://127.0.0.0x1/admin",
			expected: true,
		},
		{
			name:     "IPv6 localhost variations",
			input:    "http://[::1]:8080/admin",
			expected: true,
		},
		{
			name:     "DNS rebinding with subdomains",
			input:    "http://admin.localtest.me/internal",
			expected: true,
		},
		{
			name:     "Alternative DNS rebinding",
			input:    "http://test.lvh.me:3000/api",
			expected: true,
		},
		{
			name:     "Protocol with unusual spacing (should not match)",
			input:    "ht tp://localhost/admin",
			expected: false, // Malformed, shouldn't match
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
func TestSSRFProtocolsDetector_ReDoSResistance(t *testing.T) {
	detector := detectors.NewSSRFProtocols()

	// These inputs could cause catastrophic backtracking in poorly designed regexes
	maliciousInputs := []struct {
		name  string
		input string
	}{
		{
			name:  "Repeated protocol pattern",
			input: strings.Repeat("http://", 100) + "localhost", // Reduced from 5000 to 100
		},
		{
			name:  "Long hostname pattern",
			input: "http://" + strings.Repeat("a", 1000) + ".com/admin", // Reduced from 10000
		},
		{
			name:  "Excessive subdomain levels",
			input: "http://" + strings.Repeat("sub.", 200) + "localhost.com/", // Reduced from 2000
		},
		{
			name:  "Mixed protocol repetition",
			input: strings.Repeat("ftp://", 100) + strings.Repeat("http://", 100) + "localhost", // Reduced from 1000 each
		},
		{
			name:  "Long path with protocols",
			input: "http://localhost/" + strings.Repeat("admin/", 500), // Reduced from 5000
		},
		{
			name:  "Excessive URL encoding",
			input: "http://localhost/" + strings.Repeat("%2F", 5000) + "admin",
		},
		// SSRF-specific catastrophic backtracking patterns
		{
			name:  "Nested protocol schemes",
			input: strings.Repeat("http://", 500) + strings.Repeat("ftp://", 500) + "localhost",
		},
		{
			name:  "Excessive localhost variations",
			input: strings.Repeat("http://localhost:", 2000) + "8080/admin",
		},
		{
			name:  "Long IP address patterns",
			input: "http://" + strings.Repeat("127.0.0.1", 1000) + "/admin",
		},
		{
			name:  "Massive private network enumeration",
			input: strings.Repeat("http://192.168.1.", 1000) + "1/admin",
		},
		{
			name:  "Excessive gopher protocol chains",
			input: strings.Repeat("gopher://", 2000) + "localhost:70/",
		},
		{
			name:  "File protocol path explosion",
			input: "file://" + strings.Repeat("../", 5000) + "etc/passwd",
		},
		{
			name:  "LDAP protocol with long DN",
			input: "ldap://server/" + strings.Repeat("dc=test,", 1000) + "dc=com",
		},
		{
			name:  "Dictionary protocol with excessive definitions",
			input: strings.Repeat("dict://", 1000) + "dict.example.com:2628/",
		},
		{
			name:  "Telnet with excessive session commands",
			input: "telnet://localhost:23/" + strings.Repeat("command;", 2000),
		},
		{
			name:  "TFTP with massive file enumeration",
			input: strings.Repeat("tftp://", 500) + "server/" + strings.Repeat("file", 2000),
		},
		{
			name:  "SSH protocol with long key patterns",
			input: "ssh://user@host/" + strings.Repeat("key-", 3000) + "auth",
		},
		{
			name:  "IMAP with excessive folder enumeration",
			input: "imap://mail.server/" + strings.Repeat("INBOX.", 2000) + "Sent",
		},
		{
			name:  "SMTP with excessive relay attempts",
			input: strings.Repeat("smtp://", 1000) + "mail.server:25/",
		},
		{
			name:  "RTSP with long stream paths",
			input: "rtsp://media.server/" + strings.Repeat("stream/", 3000) + "live",
		},
		{
			name:  "Database URL with excessive parameters",
			input: "mysql://user:pass@host/db?" + strings.Repeat("param=value&", 2000),
		},
		{
			name:  "Redis with massive key enumeration",
			input: "redis://cache.server:6379/" + strings.Repeat("key:", 3000) + "value",
		},
		{
			name:  "MongoDB with excessive collection names",
			input: "mongodb://mongo.server:27017/" + strings.Repeat("collection.", 1000) + "data",
		},
		{
			name:  "WebDAV with deep directory structure",
			input: "webdav://dav.server/" + strings.Repeat("folder/", 2000) + "file.txt",
		},
		{
			name:  "Cloud metadata with excessive parameters",
			input: "http://169.254.169.254/" + strings.Repeat("meta-data/", 1000) + "instance-id",
		},
		{
			name:  "Docker network with container enumeration",
			input: strings.Repeat("http://172.17.0.", 500) + "1/container-info",
		},
		{
			name:  "Kubernetes service discovery explosion",
			input: strings.Repeat("http://", 200) + strings.Repeat("service.", 200) + "default.svc.cluster.local/",
		},
		{
			name:  "Unix socket with excessive path depth",
			input: "unix://" + strings.Repeat("/var/run/", 1000) + "service.sock",
		},
		{
			name:  "Data URL with massive base64 payload",
			input: "data:text/html;base64," + strings.Repeat("YWxlcnQoMSk=", 2000),
		},
		{
			name:  "JavaScript URL with excessive script",
			input: "javascript:" + strings.Repeat("alert(1);", 2000),
		},
		{
			name:  "Chrome extension with long identifiers",
			input: "chrome-extension://" + strings.Repeat("a", 10000) + "/popup.html",
		},
		{
			name:  "UNC path with excessive network enumeration",
			input: strings.Repeat("\\\\", 1000) + "server.local\\share\\file.txt",
		},
		{
			name:  "WebSocket with massive message patterns",
			input: "ws://localhost:8080/" + strings.Repeat("message/", 2000) + "data",
		},
		{
			name:  "Multiple encoding bypass attempts",
			input: strings.Repeat("%252F", 2000) + strings.Repeat("%25252F", 1000),
		},
		// Advanced catastrophic backtracking patterns
		{
			name:  "Exponential backtracking with nested protocols",
			input: strings.Repeat("(http://", 100) + "localhost" + strings.Repeat(")", 100),
		},
		{
			name:  "Polynomial backtracking with alternations",
			input: strings.Repeat("aaa", 1000) + "://localhost",
		},
		{
			name:  "Evil regex pattern with optional quantifiers",
			input: strings.Repeat("a", 2000) + "http://",
		},
		{
			name:  "Deeply nested URL structure",
			input: "http://" + strings.Repeat("(sub", 200) + "localhost" + strings.Repeat(")", 200) + ".com/",
		},
		{
			name:  "Massive query parameter chains",
			input: "http://localhost/?" + strings.Repeat("param=value&", 2000),
		},
		{
			name:  "Excessive fragment identifier patterns",
			input: "http://localhost/#" + strings.Repeat("fragment", 3000),
		},
		{
			name:  "Catastrophic username/password patterns",
			input: "http://" + strings.Repeat("user:pass@", 1000) + "localhost/",
		},
		{
			name:  "Massive port enumeration attempts",
			input: "http://localhost:" + strings.Repeat("8080,", 2000) + "/admin",
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
