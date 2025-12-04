package detectors

import "regexp"

type NoSQLInjectionDetector struct {
	regex *regexp.Regexp
}

func NewNoSQLInjection() *NoSQLInjectionDetector {
	// ReDoS-safe NoSQL injection detection - prevents catastrophic backtracking
	pattern := `(?i)` + // Case insensitive
		`(` +
		// MongoDB query operators - in JSON/object context
		`(?:[\{\[,]\s*["']?|\b)\$(?:where|ne|gt|gte|lt|lte|in|nin|exists|regex|size|all|elemMatch|mod|type|text|search)(?:["']?\s*:|=)` + `|` +
		// MongoDB logical operators - with array context
		`\$(?:and|or|not|nor)\s*:\s*\[` + `|` +
		// MongoDB update operators - in object context
		`(?:[\{\[,]\s*["']?|\b)\$(?:set|unset|push|pull|pop|addToSet|inc|mul|rename|min|max|currentDate)(?:["']?\s*:|=)` + `|` +
		// JavaScript injection in NoSQL context
		`function\s*\(\s*[^)]{0,50}\)\s*\{[^}]{0,200}\}` + `|` +
		`this\.[a-zA-Z_][a-zA-Z0-9_.]{0,50}` + `|` +
		// CouchDB/PouchDB injection patterns
		`_(?:design|view|update|list|show|filter|validate_doc_update)/[a-zA-Z0-9_-]{1,50}` + `|` +
		`emit\s*\([^)]{0,100}\)` + `|` +
		// MongoDB specific functions
		`\bObjectId\s*\([^)]{0,50}\)` + `|` +
		`\bISODate\s*\([^)]{0,50}\)` + `|` +
		`\bNumberLong\s*\([^)]{0,50}\)` + `|` +
		`\bBinData\s*\([^)]{0,100}\)` + `|` +
		// JSON injection patterns
		`[\{\[].*?["']\$[a-zA-Z_][a-zA-Z0-9_]*["']` + `|` +
		`[\{\[].*?["'][a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_]` + `|` +
		// NoSQL command injection
		`\bdb\.[a-zA-Z_][a-zA-Z0-9_]*\.(?:find|insert|update|remove|drop|createIndex|aggregate)\s*\(` + `|` +
		`\bcollection\.(?:find|insert|update|remove|drop|createIndex|aggregate)\s*\(` + `|` +
		// Map-Reduce injection
		`\bmapreduce\s*\(` + `|` +
		`["']?(?:map|reduce)["']?\s*:\s*function\s*\(` + `|` +
		// Aggregation pipeline injection
		`(?:[\{\[]\s*["']?|\b)\$(?:match|group|sort|limit|skip|project|unwind|lookup|facet|out|merge)(?:["']?\s*:|=)` + `|` +
		// BSON injection patterns
		`(?:[\{\[,]\s*["']?|\b)\$(?:binary|date|decimal|double|int|long|objectId|regex|timestamp|undefined)(?:["']?\s*:|=)` + `|` +
		// MongoDB shell commands
		`\b(?:use|show|help|load)\s+[a-zA-Z_][a-zA-Z0-9_.-]{0,50}` + `|` +
		// NoSQL tautologies
		`\{\s*(?:["']?\$(?:gt|gte|lt|lte|ne)["']?\s*:\s*(?:null|0|""|\[\]|\{\})|["']?\$exists["']?\s*:\s*(?:true|false))\s*\}` + `|` +
		// Injection via regex
		`\{\s*["']?\$regex["']?\s*:` + `|` +
		`\{\s*["']?\$options["']?\s*:` + `|` +
		// JavaScript code execution
		`eval\s*\(\s*["'][^"']{0,200}["']\s*\)` + `|` +
		`Function\s*\([^)]{0,200}\)` + `|` +
		// Time-based injection
		`sleep\s*\(\s*[0-9.]{1,10}\s*\)` + `|` +
		// Error-based injection patterns
		`\{\s*["']?\$where["']?\s*:\s*["'].*?["']\s*\}` + `|` +
		// File system access
		`load\s*\(\s*["'][^"']{0,100}["']\s*\)` + `|` +
		// MongoDB GridFS injection
		`\bgridfs\.(?:files|chunks)\b` + `|` +
		// NoSQL authentication bypass - URL-encoded
		`(?:password|username|user|login)\[?\$ne\]?=` + `|` +
		`(?:password|username|user|login)\[?\$gt\]?=` + `|` +
		// CouchDB endpoints
		`/_(?:all_dbs|session|uuids|stats|utils|log|config)\b` + `|` +
		// Redis commands
		`\b(?:eval|evalsha)\s+["'][^"']{0,200}["']` + `|` +
		`\b(?:script|config|debug|shutdown|flushdb|flushall)\s+\w` + `|` +
		// Cassandra CQL
		`\b(?:select|insert|update|delete|create|drop|alter|grant|revoke)\s+[^;]{1,100};` + `|` +
		// DocumentDB functions
		`\b(?:IS_ARRAY|IS_BOOL|IS_DEFINED|IS_NULL|IS_NUMBER|IS_OBJECT|IS_PRIMITIVE|IS_STRING)\s*\(\s*[a-zA-Z_]` + `|` +
		// Neo4j Cypher - only when followed by typical query patterns
		`\b(?:match|create|merge)\s+\([a-zA-Z_]` + `|` +
		`\b(?:delete|set|remove|with|return)\s+[a-zA-Z_]` + `|` +
		`\bwhere\s+[a-zA-Z_].*?[><=]` + `|` +
		`\border\s+by\s+[a-zA-Z_]` + `|` +
		`\b(?:limit|skip)\s+[0-9]` +
		`)`

	return &NoSQLInjectionDetector{
		regex: regexp.MustCompile(pattern),
	}
}

func (d *NoSQLInjectionDetector) Name() string {
	return "nosql_injection"
}

func (d *NoSQLInjectionDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}