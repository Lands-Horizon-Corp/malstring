package detectors

import "regexp"

type CommandDetector struct {
	regex *regexp.Regexp
}

func NewCmd() *CommandDetector {
	// ReDoS-safe command injection detection - prevents catastrophic backtracking
	pattern := `(?i)` + // Case insensitive
		`(` +
		`[;&|]{1,2}` + `|` +
		`\$\([^)]{0,50}\)` + `|` +
		`\x60[^\x60]{0,50}\x60` + `|` +
		`\b(?:sh|bash|zsh|csh|tcsh|ksh|fish)\s*(?:-[a-z]|--\w+)` + `|` +
		`\b(?:sh|bash|zsh|csh|tcsh|ksh|fish)\s+(?:-c|--command)\s*["']?[a-zA-Z0-9._/-]` + `|` +
		`[<>]\([^)]{0,30}\)` + `|` +
		`[0-9]{0,2}(?:>>?|<<?)\s*(?:/(?:etc|dev|tmp|var)/|&[0-9]|\.\./|\$)` + `|` +
		`\$\{[A-Z_][A-Z0-9_]{0,20}\}` + `|` +
		`\$[A-Z_][A-Z0-9_]{0,20}\b` + `|` +
		`export\s+[A-Z_][A-Z0-9_]{0,20}=` + `|` +
		`\b(?:rm|rmdir|mv|cp)\s+(?:[/-]|\.{1,2}/|\$|~|\w|\p{L})` + `|` +
		`\b(?:chmod|chown)\s+(?:[0-9]{3,4}\s+|\w+:\w+\s+)` + `|` +
		`\bkill(?:all)?\s+(?:-[a-zA-Z$]+(?:\s+[0-9$]+)?|[0-9$]+)` + `|` +
		`\b(?:wget|curl)\s+(?:-[a-zA-Z]+\s+)*https?://` + `|` +
		`\b(?:nc|netcat)\s+(?:-[a-zA-Z]+\s+)*[0-9.]{7,15}\s+[0-9]{1,5}` + `|` +
		`\b(?:python|perl|ruby|php|node)\s+(?:-[a-zA-Z]+\s+)*[a-zA-Z0-9._/-]{1,}\.(?:py|pl|rb|php|js)` + `|` +
		`\b(?:python|perl|ruby|php|node)\s+-[cre]\s+` + `|` +
		`\bruby\s+-[a-z]*socket` + `|` +
		`\b(?:cat|head|tail|grep|awk|sed|find)\s+(?:/[a-zA-Z0-9._/-]{1,}|\.{1,2}/|\$|\*|~)` + `|` +
		`\b(?:tar|gzip|gunzip|zip|unzip|7z)\s+(?:-[a-zA-Z]+\s+)*[a-zA-Z0-9._/-]{1,}` + `|` +
		`\b(?:uname|whoami|id|pwd|env|printenv)\b(?:\s|$|[;&|])` + `|` +
		`\b(?:apt|yum|dnf|pacman|brew|pip|npm)\s+(?:install|remove|update|upgrade)\s+` + `|` +
		`\b(?:nohup|screen|tmux)\s+[a-zA-Z0-9._/-]{1,}` + `|` +
		`\|\s*(?:sh|bash|python|perl|ruby|php)\b` + `|` +
		`\b(?:base64|xxd|hexdump)\s+(?:-[a-zA-Z]+\s+)*[a-zA-Z0-9._/-]{1,}` + `|` +
		`\b(?:crontab|at|batch)\s+[a-zA-Z0-9._/-]{1,}` + `|` +
		`\b(?:vi|vim|emacs|nano)\s+[a-zA-Z0-9._/-]{1,}` + `|` +
		`/bin/(?:sh|bash)\s*[0-9<>&|]+` + `|` +
		`\b(?:cmd|powershell)\s*(?:/[ck]|-[c]|--command)\s*` + `|` +
		`\b(?:include|require)\s*\(?["']/` + `|` +
		`\b(?:mysql|psql|sqlite3|sqlcmd)\s+(?:-[a-zA-Z]+\s+)*[a-zA-Z0-9._/-]{1,}` + `|` +
		`\b(?:systemctl|chkconfig)\s+[a-zA-Z0-9._-]{2,}(?:\s+(?:start|stop|restart|reload|enable|disable|status))?(?:\s|$)` + `|` +
		`\bservice\s+[a-zA-Z0-9._-]{2,}\s+(?:start|stop|restart|reload|enable|disable|status)(?:\s|$)` +
		`)`

	return &CommandDetector{
		regex: regexp.MustCompile(pattern),
	}
}

func (d *CommandDetector) Name() string {
	return "command_injection"
}

func (d *CommandDetector) Check(input string) bool {
	return d.regex.MatchString(input)
}
