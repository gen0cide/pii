package pii

// RuleSet creates a map of multiple rules
type RuleSet map[string]Rule

// Rule defines a matching requirement
type Rule struct {
	Name        string   `json:"name,omitempty" csv:"name"`
	Description string   `json:"description,omitempty" csv:"description"`
	Severity    int      `json:"severity,omitempty" csv:"severity"`
	Filter      Matcher  `json:"-"`
	Exporter    Exporter `json:"-"`
}

// Hits enumerates all rules within a ruleset returning any matching rules
func (r RuleSet) Hits(s string) []Rule {
	matchedRules := []Rule{}
	for _, rule := range r {
		if rule.Filter(s) {
			matchedRules = append(matchedRules, rule)
		}
	}
	return matchedRules
}

// Exporter is an extraction helper function to pull features matched by a Matcher
type Exporter func(s string) []string
