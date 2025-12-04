package malstring

type InjectionResult struct {
	SQLi                 bool `json:"sql_injection"`
	CommandInjection     bool `json:"command_injection"`
	PathTraversal        bool `json:"path_traversal"`
	ScriptInjection      bool `json:"script_injection"`
	NoSQLInjection       bool `json:"nosql_injection"`
	SSRFProtocols        bool `json:"ssrf_protocols"`
	Log4Shell            bool `json:"log4shell"`
	GraphQLInjection     bool `json:"graphql_injection"`
	Deserialization      bool `json:"deserialization"`
	TemplateInjection    bool `json:"template_injection"`
	LDAPInjection        bool `json:"ldap_injection"`
	XPathInjection       bool `json:"xpath_injection"`
	XXE                  bool `json:"xxe"`
	RCE                  bool `json:"rce_attack"`
	PrototypePollution   bool `json:"prototype_pollution"`
	CRLFInjection        bool `json:"crlf_injection"`
	OpenRedirect         bool `json:"open_redirect"`
	UnicodeHomoglyph     bool `json:"unicode_homoglyph"`
	MassAssignment       bool `json:"mass_assignment"`
	HTMLInjection        bool `json:"html_injection"`
	DirectoryEnumeration bool `json:"directory_enumeration"`
	Shellshock           bool `json:"shellshock"`
	JWTTamper            bool `json:"jwt_tamper"`
	EmailInjection       bool `json:"email_injection"`
	ReDoS                bool `json:"redos"`
	FuzzingSignature     bool `json:"fuzzing_signature"`
	BinaryPayload        bool `json:"binary_payload"`
	UnicodeBidi          bool `json:"unicode_bidi"`
	OversizedInput       bool `json:"oversized_input"`
}

type DetectionResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}

type Detector interface {
	Name() string
	Check(input string) bool
}
