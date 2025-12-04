package detectors

import (
	"regexp"

	"github.com/Lands-Horizon-Corp/malstring"
)

// deserializationDetector implements detection for deserialization attacks
type deserializationDetector struct {
	pattern *regexp.Regexp
}

// NewDeserialization creates a new deserialization attack detector
func NewDeserialization() malstring.Detector {
	// Enhanced pattern with comprehensive detection
	pattern := `(?i)(` +
		// Java serialization markers
		`rO0ABX|ACED00|AAEAAAD|` +
		// Java dangerous classes and packages
		`javax\.management|BadAttributeValueExpException|` +
		`java\.util\.PriorityQueue|java\.security\.SignedObject|` +
		`java\.lang\.invoke\.SerializedLambda|` +
		`com\.sun\.rowset|JdbcRowSetImpl|` +
		`org\.apache\.commons\.collections|` +
		`ChainedTransformer|InvokerTransformer|` +
		// .NET dangerous classes
		`System\.Configuration\.Install\.AssemblyInstaller|` +
		`System\.Activities\.Presentation\.WorkflowDesigner|` +
		`System\.Management\.Automation\.PSObject|` +
		`System\.CodeDom\.Compiler|ObjectDataProvider|` +
		`ResourceDictionary|` +
		// PHP serialization patterns
		`O:\d+:|a:\d+:\{|s:\d+:|` +
		// Python patterns
		`pickle\.loads|__reduce__|subprocess\.Popen|os\.system|` +
		// Reflection and code execution
		`Class\.forName|getClass\(\)\.forName|` +
		`eval\s*\(|exec\s*\(|` +
		`Runtime\.getRuntime|ProcessBuilder|` +
		// JNDI and protocol injection
		`jndi:|ldap://|rmi://|` +
		// Serialization frameworks
		`node-serialize|serialize-javascript|` +
		// Template engines
		`freemarker\.template|velocity\.runtime` +
		`)`

	compiled := regexp.MustCompile(pattern)

	return &deserializationDetector{
		pattern: compiled,
	}
}

// Name returns the name of this detector
func (d *deserializationDetector) Name() string {
	return "deserialization"
}

// Check analyzes input for deserialization attack patterns
func (d *deserializationDetector) Check(input string) bool {
	return d.pattern.MatchString(input)
}
