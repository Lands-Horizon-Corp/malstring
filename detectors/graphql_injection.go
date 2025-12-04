package detectors

import "regexp"

type GraphQLInjectionDetector struct {
	regex *regexp.Regexp
}

func NewGraphQLInjection() *GraphQLInjectionDetector {
	// ReDoS-safe GraphQL injection detection patterns
	pattern := `(?i)` + // Case insensitive
		`(` +
		// Core GraphQL introspection attacks
		`\b__(?:schema|type|field|args|typename|directive|inputvalue|enumvalue)\b` + `|` +
		// Basic GraphQL operations with structure
		`\b(?:mutation|query|subscription)\s*[\{\(]` + `|` +
		// Fragment injection with structure
		`\bfragment\s+\w+\s+on\s+\w+\s*\{` + `|` +
		`\.\.\.\s*(?:\w+\s*\{|\w+\s*$|on\s+\w+)` + `|` +
		// Directive injection
		`@(?:include|skip|deprecated|auth|cost|rate)\s*\(` + `|` +
		`@\w+\s*\([^)]*(?:bypass|skip|ignore|disable|admin|secret)` + `|` +
		// Query depth abuse (4+ levels)
		`\{\s*\w+\s*\{\s*\w+\s*\{\s*\w+\s*\{` + `|` +
		// Field alias injection with braces
		`\w+\s*:\s*\w+\s*[\{\(]` + `|` +
		// Variable injection with GraphQL types
		`\$\w+\s*:\s*(?:String|Int|Float|Boolean|ID)[\!\]]?` + `|` +
		// Schema definition keywords with structure (more flexible)
		`\b(?:type|union|interface|enum|input|scalar|extend)\s+\w+(?:\s*[\{\=]|\s*implements|\s*$)` + `|` +
		// Basic mutations and operations (more flexible)
		`\b(?:mutation|query|subscription)\s+\w+\s*[\{\(]` + `|` +
		// Complex nested queries (3+ levels) - must be longer than single chars
		`\{\s*\w{2,}(?:\([^)]*\))?\s*\{\s*\w+(?:\([^)]*\))?\s*\{\s*\w+` + `|` +
		// Dangerous subscription patterns
		`\bsubscription\s*\{[^}]*(?:admin|secret|internal|private)` + `|` +
		// Batch query injection
		`\[\s*\{\s*"(?:query|mutation)"\s*:` + `|` +
		// JSON structure with GraphQL
		`[\{\[]\s*"(?:query|mutation|variables|operationName)"\s*:` + `|` +
		// Schema root definition
		`\bschema\s*\{\s*(?:query|mutation|subscription)\s*:` + `|` +
		// Dangerous variables
		`"variables"\s*:\s*\{[^}]*(?:admin|root|system|debug)` + `|` +
		// Field with dangerous arguments
		`\w+\s*\([^)]*(?:limit|offset|where|filter)[^)]*\)` + `|` +
		// Dangerous field access with dots
		`\b(?:admin|secret|system)\.\w+` + `|` +
		// Auth bypass patterns
		`@(?:auth|rate|cost)\s*\([^)]*(?:bypass|skip|ignore|disable)` + `|` +
		`@rate\s*\([^)]*(?:limit|max|burst)\s*:\s*[0-9]{4,}` + `|` +
		`@cost\s*\([^)]*(?:complexity|depth)\s*:\s*[0-9]{3,}` + `|` +
		// Resolver functions
		`__resolve(?:Type|Field|Args|Reference)\s*\(` + `|` +
		// Dangerous resolver injection
		`resolver\s*:\s*(?:function|eval|exec)` + `|` +
		// Template injection patterns
		`\{\{[^}]*(?:process|global|require|eval)` + `|` +
		// Database injection patterns
		`(?:find|aggregate|update|insert|delete)One?\s*\(\s*\{[^}]*\$` + `|` +
		`(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.*(?:WHERE|FROM|INTO)` + `|` +
		// File system access
		`(?:readFile|writeFile|require|import)\s*\([^)]*\.\.` + `|` +
		// Code execution
		`(?:eval|exec|spawn|fork)\s*\([^)]*(?:child_process|vm|buffer)` + `|` +
		// LDAP injection
		`\([^)]*(?:uid|cn|dn|objectClass)\s*=\s*[^)]*\*` + `|` +
		// XSS patterns (simplified)
		`<(?:script|iframe|img|svg|object|embed)[^>]*(?:src|href|on\w+)\s*=` + `|` +
		// Path traversal (including URL encoded)
		`(?:\.\.\/|\.\.\\|%2e%2e|%2f|%5c){2,}` + `|` +
		// Information disclosure
		`__(?:schema|introspection|debug|version|config|env)` + `|` +
		// Timing attacks
		`(?:sleep|delay|wait|timeout)\s*\([^)]*[0-9]{4,}` + `|` +
		// Resource exhaustion (simplified)
		`(?:Array|Buffer|String|Object)\.(?:from|repeat|allocUnsafe)\s*\([^)]*[0-9]{6,}` + `|` +
		// Large strings (base64-like)
		`["'][a-zA-Z0-9+/=]{500,}["']` + `|` +
		// Prototype pollution
		`(?:constructor|__proto__|prototype)\[["']` + `|` +
		// Template expression injection
		`\$\{[^}]*(?:process|global|require|eval|function)` +
		`)`

	return &GraphQLInjectionDetector{
		regex: regexp.MustCompile(pattern),
	}
}

func (d *GraphQLInjectionDetector) Name() string {
	return "graphql_injection"
}

func (d *GraphQLInjectionDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}
