package types

type RiskRule interface {
	Category() *RiskCategory
	SupportedTags() []string
	GenerateRisks(*Model) ([]*Risk, error)
}

type RiskRules map[string]RiskRule

func (what RiskRules) Merge(rules RiskRules) RiskRules {
	for key, value := range rules {
		what[key] = value
	}

	return what
}
