package test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestNewGraphQLInjection(t *testing.T) {
	detector := detectors.NewGraphQLInjection()
	if detector == nil {
		t.Fatal("NewGraphQLInjection() returned nil")
	}
}

func TestGraphQLInjectionDetector_Name(t *testing.T) {
	detector := detectors.NewGraphQLInjection()
	expected := "graphql_injection"
	if detector.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, detector.Name())
	}
}

func TestGraphQLInjectionDetector_Check(t *testing.T) {
	detector := detectors.NewGraphQLInjection()

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		// Positive cases - should detect GraphQL injection
		{
			name:     "Introspection query __schema",
			input:    "{ __schema { types { name } } }",
			expected: true,
		},
		{
			name:     "Introspection __type query",
			input:    "{ __type(name: \"User\") { fields { name } } }",
			expected: true,
		},
		{
			name:     "Introspection __typename",
			input:    "{ user { id __typename } }",
			expected: true,
		},
		{
			name:     "Deep query nesting (depth bomb)",
			input:    "{ user { posts { comments { replies { author { posts { title } } } } } } }",
			expected: true,
		},
		{
			name:     "Fragment injection",
			input:    "fragment UserFields on User { id name email }",
			expected: true,
		},
		{
			name:     "Inline fragment injection",
			input:    "{ ... on User { id name } }",
			expected: true,
		},
		{
			name:     "Directive injection @include",
			input:    "{ user @include(if: true) { name } }",
			expected: true,
		},
		{
			name:     "Directive injection @skip",
			input:    "{ posts @skip(if: false) { title } }",
			expected: true,
		},
		{
			name:     "Custom directive injection",
			input:    "{ user @auth(role: \"admin\") { secretData } }",
			expected: true,
		},
		{
			name:     "Mutation injection",
			input:    "mutation DeleteUser { deleteUser(id: 1) { success } }",
			expected: true,
		},
		{
			name:     "Subscription injection",
			input:    "subscription { userUpdated { id name } }",
			expected: true,
		},
		{
			name:     "Variable injection",
			input:    "query($userId: ID!) { user(id: $userId) { name } }",
			expected: true,
		},
		{
			name:     "Alias injection",
			input:    "{ admin: user(id: 1) { name } }",
			expected: true,
		},
		{
			name:     "Union type injection",
			input:    "union SearchResult = User | Post | Comment",
			expected: true,
		},
		{
			name:     "Interface injection",
			input:    "type User implements Node & Timestamped { id name }",
			expected: true,
		},
		{
			name:     "Enum injection",
			input:    "enum Role { ADMIN USER GUEST }",
			expected: true,
		},
		{
			name:     "Input type injection",
			input:    "input UserInput { name: String email: String }",
			expected: true,
		},
		{
			name:     "Scalar injection",
			input:    "scalar DateTime",
			expected: true,
		},
		{
			name:     "Schema extension",
			input:    "extend type User { newField: String }",
			expected: true,
		},
		{
			name:     "Dangerous subscription",
			input:    "subscription { adminUpdated { secretKey } }",
			expected: true,
		},
		{
			name:     "Batch query injection",
			input:    "[{\"query\": \"{ user { name } }\"}, {\"query\": \"{ posts { title } }\"}]",
			expected: true,
		},
		{
			name:     "JSON GraphQL query",
			input:    "{\"query\": \"{ user { name } }\", \"variables\": {}}",
			expected: true,
		},
		{
			name:     "Schema definition injection",
			input:    "schema { query: Query mutation: Mutation }",
			expected: true,
		},
		{
			name:     "Variables with admin access",
			input:    "\"variables\": { \"role\": \"admin\", \"userId\": 1 }",
			expected: true,
		},
		{
			name:     "Field with dangerous arguments",
			input:    "{ users(limit: 1000, where: {role: admin}) { name } }",
			expected: true,
		},
		{
			name:     "Recursive pattern",
			input:    "{ user { friend { friend { friend { name } } } } }",
			expected: true,
		},
		{
			name:     "Dangerous field access",
			input:    "{ admin.secret.apiKey }",
			expected: true,
		},
		{
			name:     "Auth bypass directive",
			input:    "{ secretData @auth(bypass: true) }",
			expected: true,
		},
		{
			name:     "Rate limiting bypass",
			input:    "{ data @rate(limit: 99999) }",
			expected: true,
		},
		{
			name:     "Cost analysis bypass",
			input:    "{ expensiveField @cost(complexity: 1000) }",
			expected: true,
		},
		{
			name:     "Dynamic resolver injection",
			input:    "__resolveType({ type: 'User' })",
			expected: true,
		},
		{
			name:     "Custom resolver with eval",
			input:    "resolver: function(obj) { return eval(obj.code); }",
			expected: true,
		},
		{
			name:     "Template injection",
			input:    "{{ process.env.SECRET_KEY }}",
			expected: true,
		},
		{
			name:     "NoSQL injection in resolver",
			input:    "findOne({ $where: 'this.role === \"admin\"' })",
			expected: true,
		},
		{
			name:     "SQL injection in resolver",
			input:    "SELECT * FROM users WHERE id = 1 OR 1=1",
			expected: true,
		},
		{
			name:     "File system access",
			input:    "readFile('../../../etc/passwd')",
			expected: true,
		},
		{
			name:     "Remote code execution",
			input:    "exec(child_process.spawn('rm -rf /'))",
			expected: true,
		},
		{
			name:     "LDAP injection",
			input:    "(uid=admin)(|(uid=*)(userPassword=*))",
			expected: true,
		},
		{
			name:     "XSS injection",
			input:    "<script src='http://evil.com/xss.js'></script>",
			expected: true,
		},
		{
			name:     "Path traversal",
			input:    "../../../admin/config",
			expected: true,
		},
		{
			name:     "URL encoded path traversal",
			input:    "%2e%2e%2f%2e%2e%2fadmin",
			expected: true,
		},
		{
			name:     "Server info disclosure",
			input:    "{ __debug { version } }",
			expected: true,
		},
		{
			name:     "Timing attack",
			input:    "sleep(10000)",
			expected: true,
		},
		{
			name:     "Resource exhaustion",
			input:    "Array.from({length: 1000000})",
			expected: true,
		},
		{
			name:     "Large string attack",
			input:    "\"" + strings.Repeat("A", 500) + "\"",
			expected: true,
		},
		{
			name:     "Prototype pollution",
			input:    "constructor[\"prototype\"][\"isAdmin\"] = true",
			expected: true,
		},
		{
			name:     "Expression injection",
			input:    "${process.exit(1)}",
			expected: true,
		},
		{
			name:     "Case insensitive QUERY",
			input:    "QUERY { user { name } }",
			expected: true,
		},
		{
			name:     "Case insensitive MUTATION",
			input:    "Mutation { createUser { id } }",
			expected: true,
		},
		{
			name:     "Whitespace in introspection",
			input:    "{   __schema   {   types   } }",
			expected: true,
		},
		{
			name:     "Complex nested query",
			input:    "{ user(id: 1) { posts(first: 10) { comments(last: 5) { author { email } } } } }",
			expected: true,
		},

		// Negative cases - should NOT detect GraphQL injection
		{
			name:     "Normal text",
			input:    "This is just normal text about GraphQL",
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
			name:     "Regular JSON",
			input:    "{\"name\": \"John\", \"age\": 30}",
			expected: false,
		},
		{
			name:     "Normal function call",
			input:    "function add(a, b) { return a + b; }",
			expected: false,
		},
		{
			name:     "Regular schema word",
			input:    "The database schema is well designed",
			expected: false,
		},
		{
			name:     "Fragment in text",
			input:    "This text fragment contains no injection",
			expected: false,
		},
		{
			name:     "Type in documentation",
			input:    "The user type has several fields",
			expected: false,
		},
		{
			name:     "Union in description",
			input:    "The union of these concepts is important",
			expected: false,
		},
		{
			name:     "Input in form description",
			input:    "Please provide your input in the form below",
			expected: false,
		},
		{
			name:     "Scalar in math context",
			input:    "The scalar value represents magnitude",
			expected: false,
		},
		{
			name:     "Extend in general usage",
			input:    "We need to extend this functionality",
			expected: false,
		},
		{
			name:     "Query as noun",
			input:    "Your query returned no results",
			expected: false,
		},
		{
			name:     "Mutation as noun",
			input:    "Genetic mutation is a natural process",
			expected: false,
		},
		{
			name:     "Variable in programming context",
			input:    "Declare a variable to store the value",
			expected: false,
		},
		{
			name:     "Normal email address",
			input:    "user@example.com",
			expected: false,
		},
		{
			name:     "URL without injection",
			input:    "https://api.example.com/graphql",
			expected: false,
		},
		{
			name:     "Simple object notation",
			input:    "user.name",
			expected: false,
		},

		// Edge cases
		{
			name:     "Introspection at start",
			input:    "__schema { queryType }",
			expected: true,
		},
		{
			name:     "Single character field",
			input:    "{ a { b { c } } }",
			expected: false, // Too simple to be dangerous
		},
		{
			name:     "Mixed case introspection",
			input:    "{ __Schema { types } }",
			expected: true,
		},
		{
			name:     "Directive with complex condition",
			input:    "{ field @include(if: $showField) { value } }",
			expected: true,
		},
		{
			name:     "Multiple fragments",
			input:    "...UserFragment ...PostFragment",
			expected: true,
		},
		{
			name:     "Subscription with system access",
			input:    "subscription { systemEvents { type data } }",
			expected: true,
		},
		{
			name:     "Query with SQL-like syntax",
			input:    "{ users(where: \"name = 'admin' OR '1'='1'\") { id } }",
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

func TestGraphQLInjectionDetector_IntegrationWithScanner(t *testing.T) {
	detector := detectors.NewGraphQLInjection()

	testInputs := []struct {
		input    string
		expected bool
		desc     string
	}{
		{"{ __schema { types { name } } }", true, "Schema introspection"},
		{"mutation DeleteUser { deleteUser(id: 1) }", true, "Dangerous mutation"},
		{"This is normal text about GraphQL", false, "Normal text"},
		{"{ user { posts { comments } } }", true, "Deep nesting"},
		{"Just a regular JSON object", false, "Regular JSON"},
		{"fragment UserData on User { id }", true, "Fragment definition"},
		{"{\"query\": \"{ user { name } }\"}", true, "JSON GraphQL query"},
		{"Clean input without GraphQL", false, "Clean input"},
	}

	for _, test := range testInputs {
		result := detector.Check(test.input)
		if result != test.expected {
			t.Errorf("Integration test failed for %q (%s): expected %v, got %v",
				test.input, test.desc, test.expected, result)
		}
	}
}

func BenchmarkGraphQLInjectionDetector_Check(t *testing.B) {
	detector := detectors.NewGraphQLInjection()
	testInput := "{ __schema { types { name fields { name type { name } } } } }"

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		detector.Check(testInput)
	}
}

func TestGraphQLInjectionDetector_LargeInput(t *testing.T) {
	detector := detectors.NewGraphQLInjection()

	// Test with large input to ensure no performance issues
	largeInput := ""
	for range 1000 {
		largeInput += "normal text "
	}
	largeInput += "{ __schema { types } }"

	result := detector.Check(largeInput)
	if !result {
		t.Error("Should detect GraphQL injection in large input")
	}
}

// Test for false positives - legitimate content that shouldn't be flagged
func TestGraphQLInjectionDetector_FalsePositives(t *testing.T) {
	detector := detectors.NewGraphQLInjection()

	legitimateInputs := []string{
		"Learn about GraphQL schema design",
		"The query returned unexpected results",
		"Database mutation is carefully controlled",
		"Fragment of the document was missing",
		"Input validation is important for security",
		"Union types provide flexibility",
		"Scalar values are primitive data types",
		"Extend the functionality of the API",
		"Type definitions are well documented",
		"Interface segregation principle applies",
		"Enum values are predefined constants",
		"Subscription to our newsletter is free",
		"Variable naming conventions matter",
		"Alias configuration in the settings",
		"Directive guidance from management",
		"Schema validation passed successfully",
		"Normal JSON object with nested properties",
		"Regular function definitions in code",
		"Standard object property access",
		"Typical web API endpoint documentation",
		"Common programming patterns and practices",
		"Database administration and maintenance",
		"System architecture and design patterns",
		"User interface and experience design",
		"Network protocol and communication",
		"Software development lifecycle management",
	}

	for _, input := range legitimateInputs {
		result := detector.Check(input)
		if result {
			t.Errorf("False positive detected for legitimate input: %q", input)
		}
	}
}

// Test for evasion attempts
func TestGraphQLInjectionDetector_EvasionAttempts(t *testing.T) {
	detector := detectors.NewGraphQLInjection()

	evasionAttempts := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Case variation evasion",
			input:    "{ __SCHEMA { TYPES } }",
			expected: true,
		},
		{
			name:     "Mixed case introspection",
			input:    "{ __Schema { queryType { name } } }",
			expected: true,
		},
		{
			name:     "Whitespace evasion in query",
			input:    "{    __schema    {    types    {    name    }    }    }",
			expected: true,
		},
		{
			name:     "Fragment with case variation",
			input:    "Fragment UserFields ON User { id name }",
			expected: true,
		},
		{
			name:     "Directive with spacing",
			input:    "{ field  @include  ( if : true )  { value } }",
			expected: true,
		},
		{
			name:     "Mutation with case mixing",
			input:    "MuTaTiOn CreateUser { createUser(input: $input) { id } }",
			expected: true,
		},
		{
			name:     "Subscription with extra whitespace",
			input:    "subscription   {   userUpdated   {   id   }   }",
			expected: true,
		},
		{
			name:     "Query with newlines",
			input:    "{\n  __schema\n  {\n    types\n  }\n}",
			expected: true,
		},
		{
			name:     "Variable with spacing",
			input:    "query ( $userId : ID ! ) { user(id: $userId) }",
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
func TestGraphQLInjectionDetector_ReDoSResistance(t *testing.T) {
	detector := detectors.NewGraphQLInjection()

	// These inputs could cause catastrophic backtracking in poorly designed regexes
	maliciousInputs := []struct {
		name  string
		input string
	}{
		{
			name:  "Repeated schema pattern",
			input: strings.Repeat("__schema ", 1000) + "{ types }",
		},
		{
			name:  "Long field chain",
			input: "{ " + strings.Repeat("field.", 2000) + "value }",
		},
		{
			name:  "Excessive query nesting",
			input: strings.Repeat("{ user ", 500) + "name" + strings.Repeat(" }", 500),
		},
		{
			name:  "Mixed repeated patterns",
			input: strings.Repeat("query ", 500) + strings.Repeat("mutation ", 500) + "{ user }",
		},
		{
			name:  "Long fragment pattern",
			input: "fragment " + strings.Repeat("User", 1000) + " on User { id }",
		},
		{
			name:  "Excessive directive repetition",
			input: strings.Repeat("@include ", 2000) + "{ field }",
		},
		// GraphQL-specific catastrophic backtracking patterns
		{
			name:  "Nested introspection with excessive depth",
			input: strings.Repeat("{ __schema { types { fields { type ", 500) + "{ name }" + strings.Repeat(" } } } }", 500),
		},
		{
			name:  "Excessive variable definitions",
			input: "query(" + strings.Repeat("$var: String, ", 1000) + ") { user }",
		},
		{
			name:  "Deep fragment nesting",
			input: strings.Repeat("fragment F on User { ...F", 200) + strings.Repeat(" }", 200),
		},
		{
			name:  "Massive alias chain",
			input: "{ " + strings.Repeat("alias: field, ", 2000) + "name }",
		},
		{
			name:  "Excessive union definitions",
			input: strings.Repeat("union Result = User | Post | ", 500) + "Comment",
		},
		{
			name:  "Deep interface implementation",
			input: "type User implements " + strings.Repeat("Interface & ", 500) + "Node",
		},
		{
			name:  "Massive enum values",
			input: "enum Status { " + strings.Repeat("VALUE, ", 2000) + "DONE }",
		},
		{
			name:  "Long input type definition",
			input: "input UserInput { " + strings.Repeat("field: String, ", 1000) + "name: String }",
		},
		{
			name:  "Excessive subscription events",
			input: "subscription { " + strings.Repeat("event { data }, ", 1000) + "final { id } }",
		},
		{
			name:  "Massive batch query",
			input: "[" + strings.Repeat("{\"query\": \"{ user }\"},", 2000) + "{\"query\": \"{ posts }\"}]",
		},
		{
			name:  "Deep field argument nesting",
			input: "{ field(" + strings.Repeat("arg: { nested: ", 200) + "value" + strings.Repeat(" }", 200) + ") }",
		},
		{
			name:  "Excessive resolver patterns",
			input: strings.Repeat("__resolveType ", 1000) + "({ type: 'User' })",
		},
		{
			name:  "Long template injection",
			input: "{{ " + strings.Repeat("process.env.", 500) + "SECRET }}",
		},
		{
			name:  "Massive NoSQL injection",
			input: "findOne({ " + strings.Repeat("$where: 'condition', ", 1000) + "$limit: 1 })",
		},
		{
			name:  "Excessive SQL injection",
			input: "SELECT * FROM " + strings.Repeat("table JOIN subtable ON condition, ", 500) + "users",
		},
		{
			name:  "Long file path traversal",
			input: strings.Repeat("../", 1000) + "etc/passwd",
		},
		{
			name:  "Massive XSS payload",
			input: "<script>" + strings.Repeat("alert('xss');", 1000) + "</script>",
		},
		{
			name:  "Deep prototype pollution",
			input: strings.Repeat("constructor[\"prototype\"]", 500) + "[\"isAdmin\"] = true",
		},
		{
			name:  "Long expression injection",
			input: "${" + strings.Repeat("process.env.SECRET.", 500) + "KEY}",
		},
		// Advanced catastrophic backtracking patterns
		{
			name:  "Exponential backtracking with nested groups",
			input: strings.Repeat("(query { user ", 100) + "name" + strings.Repeat(" })", 100),
		},
		{
			name:  "Polynomial backtracking with alternations",
			input: strings.Repeat("aaa", 1000) + "{ __schema }",
		},
		{
			name:  "Evil regex pattern with optional quantifiers",
			input: strings.Repeat("a", 2000) + "__schema",
		},
		{
			name:  "Deeply nested GraphQL structure",
			input: "query " + strings.Repeat("(nested ", 200) + "user" + strings.Repeat(")", 200) + " { id }",
		},
		{
			name:  "Massive field selection set",
			input: "{ " + strings.Repeat("field1 field2 field3 ", 1000) + "name }",
		},
		{
			name:  "Excessive argument patterns",
			input: "{ field(" + strings.Repeat("arg1: val1 arg2: val2 ", 1000) + ") { name } }",
		},
		{
			name:  "Catastrophic directive nesting",
			input: strings.Repeat("@dir(", 500) + "value" + strings.Repeat(")", 500) + " { field }",
		},
		{
			name:  "Massive type definition chain",
			input: strings.Repeat("type User { field: SubType } type SubType { next: ", 200) + "String" + strings.Repeat(" }", 200),
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
