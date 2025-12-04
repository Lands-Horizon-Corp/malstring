package test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestNewNoSQLInjection(t *testing.T) {
	detector := detectors.NewNoSQLInjection()
	if detector == nil {
		t.Fatal("NewNoSQLInjection() returned nil")
	}
}

func TestNoSQLInjectionDetector_Name(t *testing.T) {
	detector := detectors.NewNoSQLInjection()
	expected := "nosql_injection"
	if detector.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, detector.Name())
	}
}

func TestNoSQLInjectionDetector_Check(t *testing.T) {
	detector := detectors.NewNoSQLInjection()

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		// Positive cases - should detect NoSQL injection
		{
			name:     "MongoDB $ne operator",
			input:    "{$ne: null}",
			expected: true,
		},
		{
			name:     "MongoDB $gt operator",
			input:    "{$gt: \"\"}",
			expected: true,
		},
		{
			name:     "MongoDB $where injection",
			input:    "{$where: 'this.username == \"admin\"'}",
			expected: true,
		},
		{
			name:     "Authentication bypass with $ne",
			input:    "username[$ne]=1&password[$ne]=1",
			expected: true,
		},
		{
			name:     "MongoDB tautology injection",
			input:    "db.users.find({$where: 'true'})",
			expected: true,
		},
		{
			name:     "JavaScript injection via $where",
			input:    "{$where: 'this.username == \"admin\" || 1==1'}",
			expected: true,
		},
		{
			name:     "MongoDB $lt operator",
			input:    "{age: {$lt: 30}}",
			expected: true,
		},
		{
			name:     "MongoDB $gte operator",
			input:    "{score: {$gte: 90}}",
			expected: true,
		},
		{
			name:     "MongoDB $lte operator",
			input:    "{price: {$lte: 100}}",
			expected: true,
		},
		{
			name:     "MongoDB $in operator",
			input:    "{status: {$in: ['active', 'pending']}}",
			expected: true,
		},
		{
			name:     "MongoDB $nin operator",
			input:    "{role: {$nin: ['admin', 'root']}}",
			expected: true,
		},
		{
			name:     "MongoDB $exists operator",
			input:    "{password: {$exists: true}}",
			expected: true,
		},
		{
			name:     "MongoDB $regex operator",
			input:    "{name: {$regex: /admin/}}",
			expected: true,
		},
		{
			name:     "MongoDB $size operator",
			input:    "{tags: {$size: 3}}",
			expected: true,
		},
		{
			name:     "MongoDB $all operator",
			input:    "{tags: {$all: ['tag1', 'tag2']}}",
			expected: true,
		},
		{
			name:     "MongoDB $elemMatch operator",
			input:    "{scores: {$elemMatch: {$gte: 80}}}",
			expected: true,
		},
		{
			name:     "MongoDB $and operator",
			input:    "{$and: [{age: {$gt: 18}}, {status: 'active'}]}",
			expected: true,
		},
		{
			name:     "MongoDB $or operator",
			input:    "{$or: [{status: 'A'}, {age: {$lt: 30}}]}",
			expected: true,
		},
		{
			name:     "MongoDB $not operator",
			input:    "{$not: {age: {$gte: 18}}}",
			expected: true,
		},
		{
			name:     "MongoDB $nor operator",
			input:    "{$nor: [{status: 'A'}, {age: {$lt: 30}}]}",
			expected: true,
		},
		{
			name:     "MongoDB $set operator",
			input:    "{$set: {status: 'updated'}}",
			expected: true,
		},
		{
			name:     "MongoDB $unset operator",
			input:    "{$unset: {password: ''}}",
			expected: true,
		},
		{
			name:     "MongoDB $push operator",
			input:    "{$push: {tags: 'new-tag'}}",
			expected: true,
		},
		{
			name:     "MongoDB $pull operator",
			input:    "{$pull: {tags: 'old-tag'}}",
			expected: true,
		},
		{
			name:     "MongoDB $inc operator",
			input:    "{$inc: {counter: 1}}",
			expected: true,
		},
		{
			name:     "JavaScript function in NoSQL",
			input:    "function() { return this.username == 'admin'; }",
			expected: true,
		},
		{
			name:     "This reference in NoSQL",
			input:    "this.username",
			expected: true,
		},
		{
			name:     "This property access",
			input:    "this.password",
			expected: true,
		},
		{
			name:     "CouchDB design document",
			input:    "_design/users",
			expected: true,
		},
		{
			name:     "CouchDB view",
			input:    "_view/by_username",
			expected: true,
		},
		{
			name:     "CouchDB emit function",
			input:    "emit(doc._id, doc.value)",
			expected: true,
		},
		{
			name:     "MongoDB ObjectId",
			input:    "ObjectId('507f1f77bcf86cd799439011')",
			expected: true,
		},
		{
			name:     "MongoDB ISODate",
			input:    "ISODate('2012-07-14T01:00:00+01:00')",
			expected: true,
		},
		{
			name:     "MongoDB NumberLong",
			input:    "NumberLong(2147483647)",
			expected: true,
		},
		{
			name:     "MongoDB BinData",
			input:    "BinData(0, 'JliB6gIMRuSphAD2KmhzgQ==')",
			expected: true,
		},
		{
			name:     "JSON with dollar sign",
			input:    "{\"$where\": \"this.age > 18\"}",
			expected: true,
		},
		{
			name:     "JSON with dot notation",
			input:    "{\"user.name\": \"admin\"}",
			expected: true,
		},
		{
			name:     "MongoDB find command",
			input:    "db.users.find({username: 'admin'})",
			expected: true,
		},
		{
			name:     "MongoDB insert command",
			input:    "db.users.insert({name: 'user'})",
			expected: true,
		},
		{
			name:     "MongoDB update command",
			input:    "db.users.update({_id: id}, {$set: {status: 'active'}})",
			expected: true,
		},
		{
			name:     "MongoDB remove command",
			input:    "db.users.remove({inactive: true})",
			expected: true,
		},
		{
			name:     "MongoDB drop command",
			input:    "db.users.drop()",
			expected: true,
		},
		{
			name:     "MongoDB aggregate command",
			input:    "db.users.aggregate([{$match: {age: {$gte: 18}}}])",
			expected: true,
		},
		{
			name:     "MapReduce function",
			input:    "mapreduce({map: function() {}, reduce: function() {}})",
			expected: true,
		},
		{
			name:     "Map function definition",
			input:    "map: function() { emit(this._id, 1); }",
			expected: true,
		},
		{
			name:     "Reduce function definition",
			input:    "reduce: function(key, values) { return Array.sum(values); }",
			expected: true,
		},
		{
			name:     "Aggregation $match stage",
			input:    "$match: {status: 'A'}",
			expected: true,
		},
		{
			name:     "Aggregation $group stage",
			input:    "$group: {_id: '$department', total: {$sum: '$salary'}}",
			expected: true,
		},
		{
			name:     "Aggregation $sort stage",
			input:    "$sort: {age: -1}",
			expected: true,
		},
		{
			name:     "BSON $binary type",
			input:    "$binary: 'base64data'",
			expected: true,
		},
		{
			name:     "BSON $date type",
			input:    "$date: '2021-01-01T00:00:00Z'",
			expected: true,
		},
		{
			name:     "MongoDB shell use command",
			input:    "use database_name",
			expected: true,
		},
		{
			name:     "MongoDB shell show command",
			input:    "show collections",
			expected: true,
		},
		{
			name:     "NoSQL tautology $gt null",
			input:    "{$gt: null}",
			expected: true,
		},
		{
			name:     "NoSQL exists true",
			input:    "{$exists: true}",
			expected: true,
		},
		{
			name:     "Regex injection",
			input:    "{$regex: 'admin.*'}",
			expected: true,
		},
		{
			name:     "JavaScript eval",
			input:    "eval('return true')",
			expected: true,
		},
		{
			name:     "JavaScript Function constructor",
			input:    "Function('return this.password')",
			expected: true,
		},
		{
			name:     "NoSQL sleep injection",
			input:    "sleep(5000)",
			expected: true,
		},
		{
			name:     "Load file injection",
			input:    "load('/etc/passwd')",
			expected: true,
		},
		{
			name:     "GridFS access",
			input:    "gridfs.files",
			expected: true,
		},
		{
			name:     "CouchDB all dbs",
			input:    "/_all_dbs",
			expected: true,
		},
		{
			name:     "Redis eval command",
			input:    "eval 'return redis.call(\"get\", \"key\")' 0",
			expected: true,
		},
		{
			name:     "Redis script command",
			input:    "script load 'return 1'",
			expected: true,
		},
		{
			name:     "Cassandra SELECT",
			input:    "SELECT * FROM users WHERE username = 'admin';",
			expected: true,
		},
		{
			name:     "DocumentDB IS_ARRAY",
			input:    "IS_ARRAY(c.tags)",
			expected: true,
		},
		{
			name:     "Neo4j MATCH",
			input:    "MATCH (n:User) RETURN n",
			expected: true,
		},
		{
			name:     "Neo4j CREATE",
			input:    "CREATE (n:User {name: 'John'})",
			expected: true,
		},
		{
			name:     "Case insensitive $ne",
			input:    "{$NE: null}",
			expected: true,
		},
		{
			name:     "Case insensitive $where",
			input:    "{$WHERE: 'this.id > 0'}",
			expected: true,
		},
		{
			name:     "Mixed case function",
			input:    "Function() { return True; }",
			expected: true,
		},
		{
			name:     "Mixed case ObjectId",
			input:    "objectid('507f1f77bcf86cd799439011')",
			expected: true,
		},
		{
			name:     "$where with whitespace variations",
			input:    "{   $where   :   'this.role == \"admin\"'   }",
			expected: true,
		},
		{
			name:     "MongoDB operator in middle of string",
			input:    "some text before {$ne: null} after text",
			expected: true,
		},
		{
			name:     "Example from main function equivalent",
			input:    "normal text; db.users.drop();",
			expected: true,
		},
		{
			name:     "Time-based blind injection",
			input:    "{$where: 'sleep(5000) || true'}",
			expected: true,
		},
		{
			name:     "Boolean-based blind injection",
			input:    "{username: 'admin', password: {$regex: '^a'}}",
			expected: true,
		},
		{
			name:     "Error-based injection",
			input:    "{$where: 'function() { return //.test(\"\") }'}",
			expected: true,
		},
		{
			name:     "Aggregation pipeline injection",
			input:    "[{$match: {$where: 'function() { return true; }'}}, {$project: {password: 1}}]",
			expected: true,
		},
		{
			name:     "GridFS filename injection",
			input:    "gridfs.chunks.find({filename: {$regex: '../../etc/passwd'}})",
			expected: true,
		},
		{
			name:     "BSON injection via ObjectId",
			input:    "ObjectId('4e4e1a4076e2e7567ac34bc4') && true",
			expected: true,
		},
		{
			name:     "Advanced $where injection",
			input:    "{$where: 'function() { return (function(){var date = new Date(); do { curDate = new Date(); } while(curDate - date < 5000); return Math.max(); })() }'}",
			expected: true,
		},
		{
			name:     "Server-side JavaScript injection",
			input:    "{$where: 'global.process.mainModule.require(\"child_process\").exec(\"id\")'}",
			expected: true,
		},

		// Negative cases - should NOT detect NoSQL injection
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
			name:     "Regular JSON",
			input:    "{\"name\": \"John\", \"age\": 30}",
			expected: false,
		},
		{
			name:     "Normal email",
			input:    "user@example.com",
			expected: false,
		},
		{
			name:     "Regular array",
			input:    "[1, 2, 3, 4, 5]",
			expected: false,
		},
		{
			name:     "Normal query string",
			input:    "username=john&password=secret",
			expected: false,
		},
		{
			name:     "Regular object",
			input:    "{name: 'John', email: 'john@example.com'}",
			expected: false,
		},
		{
			name:     "Database discussion",
			input:    "NoSQL databases are flexible",
			expected: false,
		},
		{
			name:     "MongoDB discussion",
			input:    "MongoDB is a document database",
			expected: false,
		},
		{
			name:     "Function word in text",
			input:    "The function of this component",
			expected: false,
		},
		{
			name:     "Collection discussion",
			input:    "This is a collection of items",
			expected: false,
		},
		{
			name:     "Document text",
			input:    "Please document your code",
			expected: false,
		},
		{
			name:     "Regular programming",
			input:    "function add(a, b) { return a + b; }",
			expected: false,
		},
		{
			name:     "Normal configuration",
			input:    "config.json contains settings",
			expected: false,
		},
		{
			name:     "Statistics discussion",
			input:    "Show me the stats for this month",
			expected: false,
		},
		{
			name:     "Session information",
			input:    "User session has expired",
			expected: false,
		},
		{
			name:     "Log file discussion",
			input:    "Check the log files for errors",
			expected: false,
		},
		{
			name:     "Utils library",
			input:    "Using utils for helper functions",
			expected: false,
		},
		{
			name:     "Design patterns",
			input:    "Design patterns in software",
			expected: false,
		},
		{
			name:     "View component",
			input:    "This view shows user data",
			expected: false,
		},
		{
			name:     "Update notification",
			input:    "Update available for download",
			expected: false,
		},
		{
			name:     "List management",
			input:    "Manage your todo list",
			expected: false,
		},
		{
			name:     "Filter results",
			input:    "Filter the search results",
			expected: false,
		},

		// Edge cases
		{
			name:     "Empty MongoDB query",
			input:    "{}",
			expected: false,
		},
		{
			name:     "Single character",
			input:    "$",
			expected: false,
		},
		{
			name:     "Mixed case operators",
			input:    "{$GT: 5, $lt: 10}",
			expected: true,
		},
		{
			name:     "Multiple operators",
			input:    "{age: {$gte: 18, $lte: 65}}",
			expected: true,
		},
		{
			name:     "Complex nested query",
			input:    "{$and: [{$or: [{status: 'A'}, {status: 'B'}]}, {age: {$gte: 18}}]}",
			expected: true,
		},
		{
			name:     "Function with complex logic",
			input:    "function() { if (this.role === 'admin') { return true; } return false; }",
			expected: true,
		},
		{
			name:     "This with array access",
			input:    "this.permissions[0]",
			expected: true,
		},
		{
			name:     "Emit with multiple parameters",
			input:    "emit([doc.year, doc.month], {count: 1, total: doc.amount})",
			expected: true,
		},
		{
			name:     "ObjectId with valid format",
			input:    "ObjectId('507f1f77bcf86cd799439011')",
			expected: true,
		},
		{
			name:     "Partial operator match",
			input:    "greater than",
			expected: false,
		},
		{
			name:     "Multiple SQL keywords",
			input:    "{$where: 'this.username == \"admin\" && this.password.match(/^a/) && sleep(5000)'}",
			expected: true,
		},
		{
			name:     "NoSQL keywords with different separators",
			input:    "test\n{$ne:\tnull}\r\n",
			expected: true,
		},
		{
			name:     "Sleep with different parameter",
			input:    "{$where: 'sleep(0.5) || true'}",
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

func TestNoSQLInjectionDetector_IntegrationWithScanner(t *testing.T) {
	detector := detectors.NewNoSQLInjection()

	testInputs := []struct {
		input    string
		expected bool
		desc     string
	}{
		{"normal text; {$where: 'true'}", true, "NoSQL injection"},
		{"user=admin&password[$ne]=null", true, "Authentication bypass"},
		{"clean input without any NoSQL", false, "Clean input"},
		{"{$gt: null}", true, "NoSQL tautology"},
		{"This is just normal text", false, "Normal text"},
		{"user@example.com and some data", false, "Normal data"},
		{"db.users.find({role: 'admin'})", true, "MongoDB command injection"},
		{"function() { return this.isAdmin; }", true, "JavaScript injection in NoSQL"},
	}

	for _, test := range testInputs {
		result := detector.Check(test.input)
		if result != test.expected {
			t.Errorf("Integration test failed for %q (%s): expected %v, got %v",
				test.input, test.desc, test.expected, result)
		}
	}
}

func BenchmarkNoSQLInjectionDetector_Check(t *testing.B) {
	detector := detectors.NewNoSQLInjection()
	testInput := "{$where: 'this.username == \"admin\" || 1==1'} && db.users.find({$or: [{role: 'admin'}, {$gt: null}]})"

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		detector.Check(testInput)
	}
}

func TestNoSQLInjectionDetector_LargeInput(t *testing.T) {
	detector := detectors.NewNoSQLInjection()

	// Test with large input to ensure no performance issues
	largeInput := ""
	for range 1000 {
		largeInput += "normal text "
	}
	largeInput += "{$where: 'true'}"

	result := detector.Check(largeInput)
	if !result {
		t.Error("Should detect NoSQL injection in large input")
	}
}

// Test for false positives - legitimate content that shouldn't be flagged
func TestNoSQLInjectionDetector_FalsePositives(t *testing.T) {
	detector := detectors.NewNoSQLInjection()

	legitimateInputs := []string{
		"Please select the appropriate function",    // Should not trigger - select without NoSQL context
		"The collection contains various documents", // Should not trigger - collection without injection
		"Database design is important",              // Should not trigger - database without NoSQL context
		"View the results in the interface",         // Should not trigger - view without NoSQL context
		"Update your profile settings",              // Should not trigger - update without NoSQL context
		"List all available options",                // Should not trigger - list without NoSQL context
		"Filter the search results",                 // Should not trigger - filter without NoSQL context
		"Document-oriented storage",                 // Should not trigger - doesn't match pattern
		"Collection-based data model",               // Should not trigger - no specific injection patterns
		"Grid file system benefits",                 // Should not trigger - grid without injection context
		"Configuration management tools",            // Should not trigger - config without injection
		"Statistical analysis results",              // Should not trigger - stats without injection
		"Session timeout settings",                  // Should not trigger - session without injection
		"Log file analysis",                         // Should not trigger - log without injection
		"Utility functions library",                 // Should not trigger - utils without injection
		"NoSQL databases are flexible",              // Should not trigger - general discussion
		"JavaScript functions are useful",           // Should not trigger - general programming
		"MongoDB is a popular database",             // Should not trigger - general discussion
	}

	for _, input := range legitimateInputs {
		result := detector.Check(input)
		if result {
			t.Errorf("False positive detected for legitimate input: %q", input)
		}
	}
}

// Test for evasion attempts
func TestNoSQLInjectionDetector_EvasionAttempts(t *testing.T) {
	detector := detectors.NewNoSQLInjection()

	evasionAttempts := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Whitespace evasion in $where",
			input:    "{  $where  :  'this.username == \"admin\"'  }",
			expected: true,
		},
		{
			name:     "Case variation evasion",
			input:    "{$Ne: null}",
			expected: true,
		},
		{
			name:     "Multiple space evasion",
			input:    "{    $gt    :    null    }",
			expected: true,
		},
		{
			name:     "Tab and newline evasion",
			input:    "{\t$where\n:\r\n'true'\t}",
			expected: true,
		},
		{
			name:     "Mixed quote evasion",
			input:    "{'$where': \"this.role == 'admin'\"}",
			expected: true,
		},
		{
			name:     "URL encoding evasion",
			input:    "username%5B%24ne%5D=null&password%5B%24ne%5D=null",
			expected: true, // Should still be detected due to pattern
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
func TestNoSQLInjectionDetector_ReDoSResistance(t *testing.T) {
	detector := detectors.NewNoSQLInjection()

	// These inputs could cause catastrophic backtracking in poorly designed regexes
	maliciousInputs := []struct {
		name  string
		input string
	}{
		{
			name:  "Repeated $where patterns",
			input: strings.Repeat("{$where:", 1000) + "'true'}" + strings.Repeat("}", 1000),
		},
		{
			name:  "Long $regex pattern",
			input: "{$regex: '" + strings.Repeat("a", 5000) + "'}",
		},
		{
			name:  "Excessive function definitions",
			input: "function() { " + strings.Repeat("return true; ", 500) + "}",
		},
		{
			name:  "Long ObjectId pattern",
			input: "ObjectId('" + strings.Repeat("a", 3000) + "')",
		},
		{
			name:  "Massive this.property chain",
			input: "this." + strings.Repeat("prop.", 1000) + "value",
		},
		{
			name:  "Long CouchDB design pattern",
			input: "_design/" + strings.Repeat("user", 1000),
		},
		{
			name:  "Excessive emit calls",
			input: "emit(" + strings.Repeat("key, ", 1000) + "value)",
		},
		{
			name:  "Long ISODate pattern",
			input: "ISODate('" + strings.Repeat("2021-01-01", 500) + "')",
		},
		{
			name:  "Massive JSON injection",
			input: "{\"" + strings.Repeat("$where", 1000) + "\": \"true\"}",
		},
		{
			name:  "Long db.collection chain",
			input: "db." + strings.Repeat("collection.", 500) + "find()",
		},
		{
			name:  "Excessive mapreduce pattern",
			input: "mapreduce({map: function() { " + strings.Repeat("emit(1,1); ", 1000) + "})",
		},
		{
			name:  "Long aggregation pipeline",
			input: "[" + strings.Repeat("{$match: {}}, ", 1000) + "{$limit: 1}]",
		},
		{
			name:  "Massive BSON pattern",
			input: "{$binary: '" + strings.Repeat("abc", 2000) + "'}",
		},
		{
			name:  "Long MongoDB shell command",
			input: "use " + strings.Repeat("database", 1000),
		},
		{
			name:  "Excessive NoSQL tautology",
			input: "{" + strings.Repeat("$gt: null, ", 1000) + "$exists: true}",
		},
		{
			name:  "Long regex options",
			input: "{$options: '" + strings.Repeat("gi", 1000) + "'}",
		},
		{
			name:  "Massive eval injection",
			input: "eval('" + strings.Repeat("return true; ", 1000) + "')",
		},
		{
			name:  "Long Function constructor",
			input: "Function('" + strings.Repeat("arg", 500) + "', 'return true')",
		},
		{
			name:  "Excessive sleep patterns",
			input: "sleep(" + strings.Repeat("5000", 1000) + ")",
		},
		{
			name:  "Long load pattern",
			input: "load('" + strings.Repeat("/path", 1000) + "/script.js')",
		},
		// Advanced catastrophic backtracking patterns targeting specific regex vulnerabilities
		{
			name:  "Exponential backtracking nested groups",
			input: strings.Repeat("({$where:", 200) + strings.Repeat("})", 200),
		},
		{
			name:  "Polynomial backtracking alternations",
			input: strings.Repeat("$where", 2000) + "X",
		},
		{
			name:  "Evil regex pattern with quantifiers",
			input: strings.Repeat("a", 3000) + "X",
		},
		{
			name:  "Nested JSON structures",
			input: strings.Repeat("{\"$", 1000) + "where\":\"true\"" + strings.Repeat("}", 1000),
		},
		{
			name:  "Massive operator chain",
			input: strings.Repeat("{$gt:", 1000) + "null" + strings.Repeat("}", 1000),
		},
		{
			name:  "Complex function overload",
			input: strings.Repeat("function(){", 1000) + "return true;" + strings.Repeat("}", 1000),
		},
		{
			name:  "ObjectId explosion",
			input: strings.Repeat("ObjectId('", 1000) + "507f1f77bcf86cd799439011'" + strings.Repeat(")", 1000),
		},
		{
			name:  "MongoDB command chaining",
			input: strings.Repeat("db.collection.", 1000) + "find()",
		},
		{
			name:  "Aggregation stage explosion",
			input: strings.Repeat("{$match:{", 500) + "$where:'true'" + strings.Repeat("}},", 500),
		},
		{
			name:  "BSON type overload",
			input: strings.Repeat("{$binary:", 1000) + "'data'" + strings.Repeat("}", 1000),
		},
		{
			name:  "CouchDB endpoint repetition",
			input: strings.Repeat("_design/", 500) + strings.Repeat("view/", 500),
		},
		{
			name:  "Redis command bombing",
			input: strings.Repeat("eval ", 1000) + strings.Repeat("'return 1' ", 1000),
		},
		{
			name:  "Cassandra injection chain",
			input: strings.Repeat("SELECT * FROM table", 500) + strings.Repeat(";", 500),
		},
		{
			name:  "DocumentDB function nesting",
			input: strings.Repeat("IS_DEFINED(", 500) + "c.field" + strings.Repeat(")", 500),
		},
		{
			name:  "Neo4j query explosion",
			input: strings.Repeat("MATCH (n) ", 1000) + strings.Repeat("RETURN n ", 1000),
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
