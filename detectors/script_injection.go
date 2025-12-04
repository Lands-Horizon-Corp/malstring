package detectors

import "regexp"

type ScriptInjectionDetector struct {
	regex *regexp.Regexp
}

func NewScriptInjection() *ScriptInjectionDetector {
	// ReDoS-safe script injection detection - prevents catastrophic backtracking
	pattern := `(?i)` + // Case insensitive
		`(` +
		// JavaScript injection patterns - atomic groups to prevent backtracking
		`<script(?:\s+[^>]{0,200})?>.*?</script>` + `|` +
		`\bjavascript\s*:\s*[a-zA-Z0-9_$(){}\[\];.'"+=\s-]{1,200}` + `|` +
		`\bon(?:load|error|click|mouseover|focus|blur|change|submit)\s*=\s*["'][^"']{1,200}["']` + `|` +
		// DOM manipulation and dangerous functions - bounded quantifiers
		`\b(?:eval|setTimeout|setInterval|Function)\s*\([^)]{0,500}\)` + `|` +
		`\bdocument\.(?:write|writeln|createElement|getElementById)\s*\([^)]{0,200}\)` + `|` +
		`\bwindow\.(?:open|location|eval|execScript)\s*(?:\(|\s*=)` + `|` +
		// XSS payload patterns - specific patterns
		`<(?:img|iframe|object|embed|form|input|meta|link)\s+[^>]*(?:src|href|action|data)\s*=\s*["']?(?:javascript|data|vbscript):` + `|` +
		`<(?:style|meta)\s+[^>]*>.*?(?:expression|behavior|@import|javascript):` + `|` +
		// Server-side script injection - atomic patterns
		`<\?\s*(?:php|=)\s+[^?]{1,200}\?>` + `|` +
		`<%(?:=|\s+)[^%]{1,200}%>` + `|` +
		`\{\{[^}]{1,200}\}\}` + `|` +
		`\{%[^%]{1,200}%\}` + `|` +
		// Python/Ruby/Perl execution patterns - bounded
		`\b(?:exec|system|popen|subprocess\.(?:run|call|Popen))\s*\([^)]{0,300}\)` + `|` +
		`\b(?:eval|compile|execfile)\s*\([^)]{0,200}\)` + `|` +
		`\b__import__\s*\([^)]{0,100}\)` + `|` +
		`\bgetattr\s*\([^)]{0,100}\)` + `|` +
		// Shell execution in scripts - specific patterns
		`\bos\.(?:system|popen|spawn|execv?p?)\s*\([^)]{0,200}\)` + `|` +
		`\bsubprocess\.(?:run|call|check_output|Popen)\s*\([^)]{0,300}\)` + `|` +
		`\bshell_exec\s*\([^)]{0,200}\)` + `|` +
		`\bpassthru\s*\([^)]{0,200}\)` + `|` +
		// Template injection patterns - atomic
		`\$\{[^}]{1,100}\}` + `|` +
		`#\{[^}]{1,100}\}` + `|` +
		`\{\{[^}]{1,100}\|[^}]{1,100}\}\}` + `|` +
		// Code injection via dangerous functions - bounded quantifiers
		`\b(?:assert|create_function|preg_replace)\s*\([^)]*?/e[^)]*\)` + `|` +
		`\b(?:include|require)(?:_once)?\s*\([^)]*?\$[^)]{1,100}\)` + `|` +
		`\bfile_(?:get_contents|put_contents)\s*\([^)]*?(?:php://|http://|ftp://)` + `|` +
		// Serialization attacks - specific patterns
		`\b(?:unserialize|pickle\.loads|yaml\.load)\s*\([^)]{0,200}\)` + `|` +
		`\bJSON\.parse\s*\([^)]{0,200}\)` + `|` +
		// NoSQL injection patterns - atomic patterns
		`\$(?:where|ne|gt|lt|gte|lte|in|nin|regex|size|all|exists)\s*:` + `|` +
		`\{\s*\$[a-zA-Z_]{2,20}\s*:\s*[^}]{1,100}\}` + `|` +
		// LDAP injection patterns - bounded
		`\([&|!]\([^)]{1,100}\)\)` + `|` +
		`[()&|!*=><~]{2,10}` + `|` +
		// XML/XXE injection patterns - specific
		`<!(?:DOCTYPE|ENTITY)\s+[^>]{1,200}>` + `|` +
		`&[a-zA-Z_][a-zA-Z0-9_]{0,50};` + `|` +
		// HTTP header injection - atomic
		`(?:Location|Set-Cookie|Content-Type)\s*:\s*[^\r\n]{1,200}[\r\n]` + `|` +
		// File inclusion patterns - bounded quantifiers
		`\b(?:include|require)\s+["'][^"']*?\.\.[\\/][^"']{0,100}["']` + `|` +
		`\b(?:readfile|file_get_contents)\s*\([^)]*?\.\.[\\/]` + `|` +
		// Expression Language injection - specific patterns
		`\$\{[^}]*?\.(?:class|getClass|forName)[^}]*?\}` + `|` +
		`#\{[^}]*?T\([^}]*?\)\.` + `|` +
		// SSTI (Server-Side Template Injection) patterns - atomic
		`\{\{[^}]*?(?:config|request|session|g)\.[^}]*?\}\}` + `|` +
		`\{\{[^}]*?(?:__class__|__bases__|__subclasses__)[^}]*?\}\}` + `|` +
		`\{%[^%]*?(?:config|request|session)[^%]*?%\}` + `|` +
		// Polyglot injection patterns - bounded
		`javascript\s*:\s*\/\*[^*]*?\*\/\s*alert\s*\([^)]{0,100}\)` + `|` +
		`data\s*:\s*text\/html\s*[;,]\s*base64\s*,\s*[A-Za-z0-9+/=]{20,}` + `|` +
		// Generic dangerous patterns - specific contexts
		`\b(?:constructor|prototype|__proto__)\s*(?:\[|\.)` + `|` +
		`\btop\s*(?:\[|\.)(?:frames|window|document)` + `|` +
		`\bparent\s*(?:\[|\.)(?:frames|window|document)` + `|` +
		// React/JSX injection patterns - atomic
		`dangerouslySetInnerHTML\s*=\s*\{\{` + `|` +
		// Vue.js injection patterns - bounded
		`v-html\s*=\s*["'][^"']{0,200}["']` + `|` +
		// Angular injection patterns - specific
		`\[\(click\)\]\s*=\s*["'][^"']{0,200}["']` + `|` +
		// Data URI schemes for code execution - atomic patterns
		`data\s*:\s*(?:text\/javascript|application\/javascript)` + `|` +
		`vbscript\s*:\s*[a-zA-Z0-9_\(\)\s.]{1,200}` +
		`)`

	return &ScriptInjectionDetector{
		regex: regexp.MustCompile(pattern),
	}
}

func (d *ScriptInjectionDetector) Name() string {
	return "script_injection"
}

func (d *ScriptInjectionDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}
