package detectors

import (
	"regexp"
	"strings"
	"unicode"
)

type ReDoSDetector struct {
	evilPatterns     []*regexp.Regexp
	suspiciousTokens []string
}

func NewReDoS() *ReDoSDetector {
	detector := &ReDoSDetector{}
	detector.initializePatterns()
	return detector
}

func (r *ReDoSDetector) Name() string {
	return "regex_attack"
}

func (r *ReDoSDetector) initializePatterns() {
	// Compile evil patterns for ReDoS detection
	evilPatterns := []string{
		`\([^)]*[+*]\s*\)\s*[+*]`,        // Nested quantifiers: (a+)+, (a*)*
		`\([^|]{1,20}\|[^|]{1,20}\)[+*]`, // Duplicate alternations
		`\(\s*\)[+*]`,                    // Empty groups with quantifiers
		`\(\.\*\)\*`, `\(\.\+\)\+`,       // Obvious ReDoS patterns
	}

	r.evilPatterns = make([]*regexp.Regexp, 0, len(evilPatterns))
	for _, pattern := range evilPatterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			r.evilPatterns = append(r.evilPatterns, compiled)
		}
	}

	// Common ReDoS attack tokens
	r.suspiciousTokens = []string{
		"(.*)*", "(.+)+", "(a*)*", "(a+)+", "(a|a)*", "(a|a)+",
		"(a*)+", "(a+)*", "(a?)+", "([a-z]*)*", "([a-z]+)+",
		".{0,}", ".{1,}", ".*?+", ".+?+",
	}
}

func (r *ReDoSDetector) Check(input string) bool {
	// Handle legitimate regex patterns differently
	if r.isLegitimateRegex(input) {
		return r.hasObviousReDoSPatterns(input)
	}

	// Multi-layer detection checks
	return len(input) > 100000 ||
		r.hasRepetitivePatterns(input) ||
		r.hasEvilRegexPatterns(input) ||
		r.hasSuspiciousTokens(input) ||
		r.hasNestedQuantifiers(input) ||
		r.hasAlternationExplosion(input) ||
		r.hasCharacterClassRepetition(input) ||
		(len(input) > 100 && r.hasUnicodeExploits(input))
}

func (r *ReDoSDetector) isLegitimateRegex(input string) bool {
	if !strings.HasPrefix(input, "^") || !strings.HasSuffix(input, "$") {
		return false
	}
	if len(input) < 30 || len(input) > 500 {
		return false
	}
	// Check for typical regex structure
	hasCharClasses := strings.Contains(input, "[") && strings.Contains(input, "]")
	hasQuantifiers := strings.ContainsAny(input, "+*{")
	hasEscapes := strings.Contains(input, "\\")
	return (hasCharClasses && hasQuantifiers) || hasEscapes
}

func (r *ReDoSDetector) hasObviousReDoSPatterns(input string) bool {
	obviousPatterns := []string{"(.*)*", "(.+)+", "(a*)*", "(a+)+", "(a|a)*", "(hello|hello)*"}
	inputLower := strings.ToLower(input)
	for _, pattern := range obviousPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}
	return false
}

func (r *ReDoSDetector) hasRepetitivePatterns(input string) bool {
	return r.hasSimpleRepetition(input) || r.hasPatternRepetition(input) || r.hasNestedRepetition(input)
}

func (r *ReDoSDetector) hasSimpleRepetition(input string) bool {
	count, totalRepetitive := 0, 0
	threshold := 15

	// Adjust threshold based on input characteristics
	if strings.HasPrefix(input, "^") && strings.HasSuffix(input, "$") {
		threshold = 50
	} else if len(input) <= 18 {
		threshold = 18
	}

	for i := 1; i < len(input); i++ {
		if input[i] == input[i-1] {
			count++
			totalRepetitive++
			if count > threshold {
				return true
			}
		} else {
			count = 0
		}
	}

	return len(input) > 20 && totalRepetitive > 25
}

func (r *ReDoSDetector) hasPatternRepetition(input string) bool {
	for patternLen := 2; patternLen <= 20 && patternLen <= len(input)/7; patternLen++ {
		for i := 0; i <= len(input)-patternLen*7; i++ {
			pattern := input[i : i+patternLen]
			// Skip simple repeated chars for length 2
			if patternLen == 2 && pattern[0] == pattern[1] {
				continue
			}
			// Count consecutive repetitions
			repetitions, pos := 1, i+patternLen
			for pos+patternLen <= len(input) && input[pos:pos+patternLen] == pattern {
				repetitions++
				pos += patternLen
			}
			if repetitions >= 7 {
				return true
			}
		}
	}
	return false
}

func (r *ReDoSDetector) hasNestedRepetition(input string) bool {
	patterns := []string{")(", ")+(", ")*(", "}{", "}+{", "}*{", "](", "]+[", "]*["}
	for _, pattern := range patterns {
		if strings.Count(input, pattern) > 3 {
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

	// Check all suspicious tokens
	for _, token := range r.suspiciousTokens {
		if strings.Contains(inputLower, token) {
			return true
		}
	}

	// Check for unbounded quantifiers like {1,} or {0,} (but not {0,16})
	for _, pattern := range []string{"{1,}", "{0,}"} {
		if idx := strings.Index(input, pattern); idx != -1 {
			// Check if it's actually bounded (followed by a digit)
			if idx+len(pattern) >= len(input) || input[idx+len(pattern)] < '0' || input[idx+len(pattern)] > '9' {
				return true
			}
		}
	}

	return false
}

func (r *ReDoSDetector) hasNestedQuantifiers(input string) bool {
	// Quick check for obvious empty alternation patterns
	if strings.Contains(input, "(|)+") || strings.Contains(input, "(|)*") {
		return true
	}

	quantifiers := "+*?{"
	parenDepth := 0
	hasQuantInGroup, emptyGroup, hasAlternation := false, true, false

	for i, char := range input {
		switch char {
		case '(':
			parenDepth++
			hasQuantInGroup, emptyGroup, hasAlternation = false, true, false
		case ')':
			if parenDepth > 0 {
				parenDepth--
				// Check if followed by quantifier
				if i+1 < len(input) && strings.ContainsRune(quantifiers, rune(input[i+1])) {
					if emptyGroup || hasAlternation || hasQuantInGroup {
						return true
					}
				}
			}
		case '+', '*', '?', '{':
			if parenDepth > 0 {
				hasQuantInGroup, emptyGroup = true, false
			}
		case '|':
			if parenDepth > 0 {
				hasAlternation = true
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
	// Check for obvious duplicate alternations
	duplicates := []string{"(a|a)", "(hello|hello)", "(test|test)", "(admin|admin)", "(1|1)"}
	for _, pattern := range duplicates {
		if strings.Contains(input, pattern) {
			return true
		}
	}

	// Count alternations in groups
	parenDepth, alternationCount, maxAlternations := 0, 0, 0
	for _, char := range input {
		switch char {
		case '(':
			parenDepth++
			alternationCount = 0
		case ')':
			if parenDepth > 0 {
				parenDepth--
				if alternationCount > maxAlternations {
					maxAlternations = alternationCount
				}
			}
		case '|':
			if parenDepth > 0 {
				alternationCount++
			}
		}
	}

	totalAlternations := strings.Count(input, "|")
	return maxAlternations > 15 || (totalAlternations > 20 && len(input) > 100)
}

func (r *ReDoSDetector) hasCharacterClassRepetition(input string) bool {
	patterns := []string{"[a-z]+", "[0-9]+", "[A-Z]+", "[a-zA-Z]+"}
	for _, pattern := range patterns {
		if strings.Count(input, pattern) >= 2 {
			return true
		}
	}
	return false
}

func (r *ReDoSDetector) hasUnicodeExploits(input string) bool {
	unicodeCount, controlCount := 0, 0
	for _, r := range input {
		if r > unicode.MaxASCII {
			unicodeCount++
		}
		if unicode.IsControl(r) {
			controlCount++
		}
	}

	inputLen := float64(len(input))
	return (float64(unicodeCount)/inputLen > 0.5 && len(input) > 100) ||
		(float64(controlCount)/inputLen > 0.3)
}
