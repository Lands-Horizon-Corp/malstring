package malstring

type Scanner struct {
	detectors []Detector
}

func NewScanner() *Scanner {
	return &Scanner{
		detectors: []Detector{},
	}
}

func (s *Scanner) Register(d Detector) {
	s.detectors = append(s.detectors, d)
}

func (s *Scanner) Scan(input string) []DetectionResult {
	results := []DetectionResult{}
	for _, d := range s.detectors {
		results = append(results, DetectionResult{
			Name:   d.Name(),
			Passed: d.Check(input),
		})
	}
	return results
}
