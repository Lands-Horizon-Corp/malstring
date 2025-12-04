package detectors

import "regexp"

type CommandDetector struct {
	regex *regexp.Regexp
}

func NewCmd() *CommandDetector {
	return &CommandDetector{
		regex: regexp.MustCompile(`(?i)(;|&&|\|\||\bsh\b|\bbash\b)`),
	}
}

func (d *CommandDetector) Name() string {
	return "command_injection"
}

func (d *CommandDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}
