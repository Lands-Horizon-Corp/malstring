package detectors

import "regexp"

type Log4ShellDetector struct {
	regex *regexp.Regexp
}

func NewLog4Shell() *Log4ShellDetector {
	// ReDoS-safe Log4Shell detection - prevents catastrophic backtracking
	pattern := `(?i)` + // Case insensitive
		`(` +
		// Basic Log4Shell JNDI injection patterns - atomic groups
		`\$\{jndi:(?:ldap|ldaps|rmi|dns|iiop)://[a-zA-Z0-9\-\.]{1,253}(?::[0-9]{1,5})?[^\}]{0,200}\}` + `|` +
		// LDAP/LDAPS JNDI lookups (most common) - bounded quantifiers
		`\$\{jndi:ldaps?://[a-zA-Z0-9\-\.]{1,253}(?::[0-9]{1,5})?/[a-zA-Z0-9\-_/]{1,100}\}` + `|` +
		// RMI JNDI lookups - atomic
		`\$\{jndi:rmi://[a-zA-Z0-9\-\.]{1,253}(?::[0-9]{1,5})?/[a-zA-Z0-9\-_/]{1,100}\}` + `|` +
		// DNS JNDI lookups - bounded
		`\$\{jndi:dns://[a-zA-Z0-9\-\.]{1,253}(?::[0-9]{1,5})?/[a-zA-Z0-9\-_/]{1,100}\}` + `|` +
		// IIOP JNDI lookups - atomic
		`\$\{jndi:iiop://[a-zA-Z0-9\-\.]{1,253}(?::[0-9]{1,5})?/[a-zA-Z0-9\-_/]{1,100}\}` + `|` +
		// CORBA/IIOP naming lookups - bounded
		`\$\{jndi:(?:corbaloc|corbaname):[a-zA-Z0-9\-\.:#/]{1,200}\}` + `|` +
		// Generic JNDI with various protocols - atomic groups
		`\$\{jndi:(?:java|http|https|file|ftp)://[^\}]{1,200}\}` + `|` +
		// Log4j lookups with nested expressions - bounded quantifiers
		`\$\{(?:env|sys|java|date|ctx|map|sd|bundle|docker|web|spring|k8s):[a-zA-Z0-9\-_\.]{1,100}(?:/[a-zA-Z0-9\-_\.]{1,100})*\}` + `|` +
		// Nested JNDI expressions (bypass attempts) - atomic
		`\$\{[^}]*\$\{jndi:[^}]{1,200}\}[^}]*\}` + `|` +
		// URL-encoded Log4Shell attempts - bounded
		`%24%7B[^%]*jndi[^%]*%3A[^%]*%2F%2F[^%]*%7D` + `|` +
		// Unicode-encoded Log4Shell attempts - atomic groups
		`\\u0024\\u007B(?:jndi|env|sys|java):[^\\]{0,100}\\u007D` + `|` +
		// Base64 encoded payloads (common bypass) - bounded quantifiers
		`\$\{base64:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\}` + `|` +
		// Script engine execution via Log4j - atomic
		`\$\{script:(?:javascript|groovy|python):[^}]{1,200}\}` + `|` +
		// Thread Context Map lookups - bounded
		`\$\{(?:mdc|ctx):[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// Marker lookups - atomic
		`\$\{marker:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// Exception message lookups - bounded quantifiers
		`\$\{exception:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// Log4j2 configuration lookups - atomic groups
		`\$\{log4j:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// JVM arguments lookups - bounded
		`\$\{jvmrunargs:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// System properties with dangerous values - atomic
		`\$\{sys:(?:java\.class\.path|java\.library\.path|java\.home|user\.dir|user\.home|os\.name)[^}]*\}` + `|` +
		// Environment variables with dangerous values - bounded quantifiers
		`\$\{env:(?:PATH|CLASSPATH|JAVA_HOME|TEMP|TMP|USER|HOME)[^}]*\}` + `|` +
		// Docker/Kubernetes specific lookups - atomic groups
		`\$\{docker:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		`\$\{k8s:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// Spring Boot lookups - bounded
		`\$\{spring:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// Web context lookups - atomic
		`\$\{web:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// Event lookups - bounded quantifiers
		`\$\{event:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// Structured data lookups - atomic groups
		`\$\{sd:[a-zA-Z0-9\-_\.@]{1,50}\}` + `|` +
		// Bundle lookups - bounded
		`\$\{bundle:[a-zA-Z0-9\-_\.]{1,50}\}` + `|` +
		// Lower/Upper case transformations with JNDI - atomic
		`\$\{(?:lower|upper):\$\{jndi:[^}]{1,200}\}\}` + `|` +
		// Evasion with whitespace/comments inside JNDI - bounded quantifiers
		`\$\{\s*jndi\s*:\s*ldaps?\s*:\s*//[^}]{1,200}\}` + `|` +
		// Obfuscated JNDI with variable substitution - atomic groups
		`\$\{[^}]*\$\{[^}]*\}[^}]*j[^}]*n[^}]*d[^}]*i[^}]*:[^}]{1,200}\}` + `|` +
		// Common obfuscation patterns for JNDI
		`\$\{[^}]*j\$\{[^}]*\}[^}]*n[^}]*d[^}]*i[^}]*:(?:ldap|rmi|dns)://[^}]{1,200}\}` + `|` +
		// Alternative syntax with different delimiters - bounded
		`%\{jndi:(?:ldap|rmi|dns)://[^%]{1,200}\}` + `|` +
		// Java deserialization gadgets via JNDI - atomic
		`\$\{jndi:ldap://[^}]*(?:CommonsCollections|CommonsBeanutils|Groovy|Spring|Rome)[^}]{0,100}\}` + `|` +
		// LDAP result referral attacks - bounded quantifiers
		`\$\{jndi:ldap://[^}]*\?[a-zA-Z0-9\-_=&]{1,200}\}` + `|` +
		// DNS exfiltration patterns - atomic groups
		`\$\{jndi:dns://[a-zA-Z0-9\-\.]*\$\{(?:env|sys):[^}]{1,50}\}[a-zA-Z0-9\-\.]*\}` + `|` +
		// Multi-stage JNDI with redirects - bounded
		`\$\{jndi:ldap://[^}]*redirect[^}]{0,100}\}` + `|` +
		// JNDI with authentication bypass - atomic
		`\$\{jndi:ldap://(?:guest|anonymous|admin)(?::[^@]*)?@[^}]{1,200}\}` + `|` +
		// Custom JNDI factories - bounded quantifiers
		`\$\{jndi:[a-zA-Z][a-zA-Z0-9\-_\.]{1,50}://[^}]{1,200}\}` + `|` +
		// Hostname/IP extraction via JNDI - atomic groups
		`\$\{hostName\}[a-zA-Z0-9\-\.]*\.(?:burpcollaborator\.net|oast\.pro|requestbin\.com)` + `|` +
		// Time-based detection evasion - bounded
		`\$\{date:[^}]{1,50}\}[a-zA-Z0-9\-]*\.(?:dnslog|ceye)\.` +
		`)`

	return &Log4ShellDetector{
		regex: regexp.MustCompile(pattern),
	}
}

func (d *Log4ShellDetector) Name() string {
	return "log4shell"
}

func (d *Log4ShellDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}
