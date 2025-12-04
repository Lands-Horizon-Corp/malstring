package detectors

import (
	"regexp"
	"strings"
	"unicode"
)

type ReDoSDetector struct {
	// Pre-compiled patterns for efficient detection
	evilPatterns     []*regexp.Regexp
	suspiciousTokens []string
}

func NewReDoS() *ReDoSDetector {
	detector := &ReDoSDetector{}
	detector.initializePatterns()
	return detector
}

func (r *ReDoSDetector) initializePatterns() {
	// Evil regex patterns known to cause exponential backtracking - ReDoS-safe detection
	evilPatternStrings := []string{
		// Nested quantifiers (a+)+ variants - bounded detection
		`\([^)]*\+\s*\)\s*\+`,
		`\([^)]*\*\s*\)\s*\+`,
		`\([^)]*\+\s*\)\s*\*`,

		// Alternation with overlapping patterns - bounded
		`\([^|]{1,20}\|[^|]{1,20}\)\+`,
		`\([^|]{1,20}\|[^|]{1,20}\)\*`,

		// Grouping with optional quantifiers - bounded
		`\([^)]{1,50}\)\?\+`,
		`\([^)]{1,50}\)\*\?`,

		// Character class variations that can cause backtracking
		`\[[^]]{1,20}\]\+\s*\[[^]]{1,20}\]\*`,

		// Word boundary exploits - bounded
		`\\b[^\\]{1,30}\\b\+`,

		// Lookahead/lookbehind patterns (if supported)
		`\(\?\=[^)]{1,30}\)`,
		`\(\?\![^)]{1,30}\)`,
	}

	r.evilPatterns = make([]*regexp.Regexp, 0, len(evilPatternStrings))
	for _, pattern := range evilPatternStrings {
		if compiled, err := regexp.Compile(pattern); err == nil {
			r.evilPatterns = append(r.evilPatterns, compiled)
		}
	}

	// Suspicious tokens that often appear in ReDoS attacks
	r.suspiciousTokens = []string{
		"(.*)*", "(.+)+", "(a*)*", "(a+)+",
		"(a|a)*", "(a|a)+", "(a*)+", "(a+)*",
		"(a?)+", "(a*)?+", "(a+)?+",
		"([a-z]*)*", "([a-z]+)+", "([0-9]*)*",
		".{0,}", ".{1,}", ".*?+", ".+?+",
	}
}

func (r *ReDoSDetector) Name() string {
	return "regex_attack"
}

func (r *ReDoSDetector) Check(input string) bool {
	// Multi-layer ReDoS detection approach

	// 1. Input length check (DoS via large input)
	if len(input) > 100000 {
		return true
	}

	// 2. Repetitive character patterns (classic ReDoS trigger)
	if r.hasRepetitivePatterns(input) {
		return true
	}

	// 3. Evil regex pattern detection
	if r.hasEvilRegexPatterns(input) {
		return true
	}

	// 4. Suspicious token detection
	if r.hasSuspiciousTokens(input) {
		return true
	}

	// 5. Nested quantifier detection
	if r.hasNestedQuantifiers(input) {
		return true
	}

	// 6. Alternation explosion detection
	if r.hasAlternationExplosion(input) {
		return true
	}

	// 7. Unicode exploitation detection
	if r.hasUnicodeExploits(input) {
		return true
	}

	return false
}

// Enhanced repetitive pattern detection
func (r *ReDoSDetector) hasRepetitivePatterns(input string) bool {
	// Multiple detection strategies for different types of repetition

	// 1. Simple character repetition (original logic enhanced)
	if r.hasSimpleRepetition(input) {
		return true
	}

	// 2. Pattern repetition (sequences that repeat)
	if r.hasPatternRepetition(input) {
		return true
	}

	// 3. Nested repetition (patterns within patterns)
	if r.hasNestedRepetition(input) {
		return true
	}

	return false
}

func (r *ReDoSDetector) hasSimpleRepetition(input string) bool {
	count := 0
	threshold := 20 // Increased threshold to reduce false positives

	for i := 1; i < len(input); i++ {
		if input[i] == input[i-1] {
			count++
			if count > threshold {
				return true
			}
		} else {
			count = 0
		}
	}
	return false
}

func (r *ReDoSDetector) hasPatternRepetition(input string) bool {
	// Detect repeating substrings that could trigger backtracking
	maxPatternLen := 20
	minRepetitions := 5

	for patternLen := 2; patternLen <= maxPatternLen && patternLen <= len(input)/minRepetitions; patternLen++ {
		for i := 0; i <= len(input)-patternLen*minRepetitions; i++ {
			pattern := input[i : i+patternLen]
			repetitions := 1
			pos := i + patternLen

			// Count consecutive repetitions
			for pos+patternLen <= len(input) && input[pos:pos+patternLen] == pattern {
				repetitions++
				pos += patternLen
			}

			if repetitions >= minRepetitions {
				return true
			}
		}
	}
	return false
}

func (r *ReDoSDetector) hasNestedRepetition(input string) bool {
	// Detect patterns like "(ab)+" repeated multiple times
	nestedPatterns := []string{
		")(", ")+(", ")*(",
		"}{", "}+{", "}*{",
		"](", "]+[", "]*[",
	}

	for _, pattern := range nestedPatterns {
		count := strings.Count(input, pattern)
		if count > 3 {
			return true
		}
	}
	return false
}

func (r *ReDoSDetector) hasEvilRegexPatterns(input string) bool {
	for _, pattern := range r.evilPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func (r *ReDoSDetector) hasSuspiciousTokens(input string) bool {
	inputLower := strings.ToLower(input)

	for _, token := range r.suspiciousTokens {
		if strings.Contains(inputLower, strings.ToLower(token)) {
			return true
		}
	}

	// Additional manual checks for patterns our regex might miss
	suspiciousPatterns := []string{
		"{1,}", "{0,}", // Unbounded quantifiers
		"[a-z]+", "[0-9]*", // Character classes with quantifiers (when multiple)
		"()+", "(())+", "(|)+", // Empty groups with quantifiers
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(input, pattern) {
			// For quantifier patterns, check context
			if strings.Contains(pattern, "{") && strings.Contains(input, pattern) {
				return true
			}
			// For empty group patterns
			if strings.HasPrefix(pattern, "(") && strings.Contains(input, pattern) {
				return true
			}
			// For character class patterns, check if there are multiple
			if strings.HasPrefix(pattern, "[") {
				count := strings.Count(input, pattern)
				if count >= 2 {
					return true
				}
			}
		}
	}

	return false
}

func (r *ReDoSDetector) hasNestedQuantifiers(input string) bool {
	// Detect nested quantifier patterns manually (more reliable than regex on regex)
	quantifiers := []rune{'+', '*', '?', '{'}

	// Look for patterns like "(pattern+)+" or "(pattern*)*" or empty groups like "()+"
	parenDepth := 0
	hasQuantifierInGroup := false
	emptyGroup := true

	for i, char := range input {
		switch char {
		case '(':
			parenDepth++
			hasQuantifierInGroup = false
			emptyGroup = true
		case ')':
			if parenDepth > 0 {
				parenDepth--
				// Check if next character is a quantifier
				if i+1 < len(input) {
					nextChar := rune(input[i+1])
					for _, q := range quantifiers {
						if nextChar == q {
							// Empty group with quantifier is always suspicious
							if emptyGroup {
								return true
							}
							// Non-empty group with quantifier inside and quantifier after
							if hasQuantifierInGroup {
								return true
							}
						}
					}
				}
			}
		case '+', '*', '?':
			if parenDepth > 0 {
				hasQuantifierInGroup = true
				emptyGroup = false
			}
		case '{':
			if parenDepth > 0 {
				hasQuantifierInGroup = true
				emptyGroup = false
			}
		case '|':
			if parenDepth > 0 {
				emptyGroup = false
			}
		default:
			if parenDepth > 0 && !unicode.IsSpace(char) {
				emptyGroup = false
			}
		}
	}
	return false
}
func (r *ReDoSDetector) hasAlternationExplosion(input string) bool {
	// Detect alternation patterns that can cause exponential blowup

	// Count alternations within groups
	parenDepth := 0
	alternationCount := 0
	maxAlternationsInGroup := 0

	for _, char := range input {
		switch char {
		case '(':
			parenDepth++
			alternationCount = 0
		case ')':
			if parenDepth > 0 {
				parenDepth--
				if alternationCount > maxAlternationsInGroup {
					maxAlternationsInGroup = alternationCount
				}
			}
		case '|':
			if parenDepth > 0 {
				alternationCount++
			}
		}
	}

	// Too many alternations in a single group can cause issues
	if maxAlternationsInGroup > 15 { // Increased threshold
		return true
	}

	// Overall alternation count - more lenient for simple patterns
	totalAlternations := strings.Count(input, "|")
	if totalAlternations > 20 && len(input) > 100 { // Added length condition
		return true
	}

	return false
}

func (r *ReDoSDetector) hasUnicodeExploits(input string) bool {
	// Detect Unicode-based ReDoS attempts

	unicodeCount := 0
	controlCharCount := 0

	for _, r := range input {
		if r > unicode.MaxASCII {
			unicodeCount++
		}
		if unicode.IsControl(r) {
			controlCharCount++
		}
	}

	// High Unicode density might indicate exploitation attempt
	if len(input) > 0 {
		unicodeDensity := float64(unicodeCount) / float64(len(input))
		if unicodeDensity > 0.5 && len(input) > 100 {
			return true
		}

		controlDensity := float64(controlCharCount) / float64(len(input))
		if controlDensity > 0.3 {
			return true
		}
	}

	return false
}
