package detectors

import "regexp"

type SSRFProtocolsDetector struct {
	regex *regexp.Regexp
}

func NewSSRFProtocols() *SSRFProtocolsDetector {
	// ReDoS-safe SSRF protocol detection - prevents catastrophic backtracking
	pattern := `(?i)` + // Case insensitive
		`(` +
		// HTTP/HTTPS protocols with dangerous hosts - atomic groups
		`\bhttps?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)` + `|` +
		// FTP protocols (dangerous for SSRF) - bounded
		`\bftp://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// File protocol access - atomic (Windows and Unix paths)
		`\bfile:///?(?:[/\\]|[a-zA-Z]:)` + `|` +
		// Gopher protocol (extremely dangerous) - bounded
		`\bgopher://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// LDAP/LDAPS protocols - atomic groups
		`\bldaps?://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// Dictionary protocol - bounded
		`\bdict://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// Telnet protocol - atomic
		`\btelnet://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// TFTP protocol - bounded
		`\btftp://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// SSH protocol - atomic
		`\bssh://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// IMAP/IMAPS protocols - bounded
		`\bimaps?://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// POP3/POP3S protocols - atomic
		`\bpop3s?://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// SMTP/SMTPS protocols - bounded
		`\bsmtps?://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// RTSP protocol - atomic
		`\brtsp://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// SCP protocol - bounded
		`\bscp://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// SFTP protocol - atomic
		`\bsftp://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// MySQL protocol - bounded
		`\bmysql://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// PostgreSQL protocol - atomic
		`\bpostgresql://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// Redis protocol - bounded
		`\bredis://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// MongoDB protocol - atomic
		`\bmongodb://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// AMQP protocol - bounded
		`\bamqps?://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// WebDAV protocols - atomic groups
		`\bwebdavs?://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// Local network ranges in URLs - IPv4 private ranges
		`\b(?:https?|ftp)://(?:10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)` + `|` +
		// Localhost variations - atomic
		`\b(?:https?|ftp)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\])` + `|` +
		// Port scanning indicators (limit to avoid false positives) - bounded quantifiers
		`\b(?:https?|ftp)://(?:localhost|127\.0\.0\.1|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)[^/]*:[1-9][0-9]{1,4}` + `|` +
		// Double URL encoding attempts (bypass filters) - atomic
		`%25(?:2[fF]|5[cC])` + `|` +
		// Triple URL encoding - bounded
		`%25%32%35(?:2[fF]|5[cC])` + `|` +
		// Unicode URL encoding bypass - atomic groups
		`%[cC][01][89aAbBcCdDeEfF][0-9a-fA-F]` + `|` +
		// Alternative IP representations (decimal, octal) - bounded
		`\b(?:https?|ftp)://(?:[0-9]{8,10}|0[0-7]{8,11})(?:/|\?|$)` + `|` +
		// Hex IP representation - atomic
		`\b(?:https?|ftp)://0x[0-9a-fA-F]{8}` + `|` +
		// Mixed IP representations - bounded
		`\b(?:https?|ftp)://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0x[0-9a-fA-F]{1,2}` + `|` +
		// IPv6 localhost variations - atomic groups
		`\b(?:https?|ftp)://\[::1\]` + `|` +
		// DNS rebinding attack patterns - bounded quantifiers
		`\b(?:https?|ftp)://[a-zA-Z0-9\-]{1,63}\.(?:localtest|lvh)\.me` + `|` +
		// Cloud metadata service endpoints - specific patterns
		`\b(?:https?|ftp)://(?:169\.254\.169\.254|metadata\.google\.internal)` + `|` +
		// AWS metadata service - atomic
		`\b(?:https?|ftp)://169\.254\.169\.254/(?:latest/meta-data|computeMetadata)` + `|` +
		// Azure metadata service - bounded
		`\b(?:https?|ftp)://169\.254\.169\.254/metadata/instance` + `|` +
		// Alibaba Cloud metadata - atomic
		`\b(?:https?|ftp)://100\.100\.100\.200/latest/meta-data` + `|` +
		// Docker internal networks - bounded
		`\b(?:https?|ftp)://172\.1[7-9]\.[0-9]{1,3}\.[0-9]{1,3}` + `|` +
		// Kubernetes internal service - atomic groups
		`\b(?:https?|ftp)://[a-zA-Z0-9\-]{1,63}\.default\.svc\.cluster\.local` + `|` +
		// Unix domain sockets via HTTP - bounded
		`\bunix://[a-zA-Z0-9/\-_\.]{1,255}` + `|` +
		// Data URLs with base64 (can be used for bypass) - atomic
		`\bdata:[^;]{1,50};base64,[a-zA-Z0-9/+=]{20,}` + `|` +
		// JavaScript protocol - bounded
		`\bjavascript:[a-zA-Z0-9()'"]{1,100}` + `|` +
		// VBScript protocol - atomic
		`\bvbscript:[a-zA-Z0-9()'"]{1,100}` + `|` +
		// MHTML protocol - bounded
		`\bmhtml:[a-zA-Z0-9\-_\.]{1,100}` + `|` +
		// Chrome extension protocols - atomic groups
		`\bchrome-extension://[a-z0-9]{32}` + `|` +
		// Firefox extension protocols - bounded
		`\bmoz-extension://[a-z0-9\-]{8,}` + `|` +
		// Edge extension protocols - atomic
		`\bms-browser-extension://[a-z0-9\-]{8,}` + `|` +
		// Network UNC paths (Windows) - bounded quantifiers
		`\\\\[a-zA-Z0-9\-\.]{1,253}\\` + `|` +
		// RTMP/RTMPS protocols - atomic
		`\brtmps?://[a-zA-Z0-9\-\.]{1,253}` + `|` +
		// WebSocket protocols with suspicious hosts - bounded
		`\bwss?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)` +
		`)`

	return &SSRFProtocolsDetector{
		regex: regexp.MustCompile(pattern),
	}
}

func (d *SSRFProtocolsDetector) Name() string {
	return "ssrf_protocols"
}

func (d *SSRFProtocolsDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}
