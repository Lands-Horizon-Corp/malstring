package detectors

import "regexp"

type SQLiDetector struct {
	regex *regexp.Regexp
}

func NewSQLi() *SQLiDetector {
	return &SQLiDetector{
		regex: regexp.MustCompile(`(?i)(union|select|sleep\(|benchmark\()`),
	}
}

func (d *SQLiDetector) Name() string {
	return "sql_injection"
}

func (d *SQLiDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}
