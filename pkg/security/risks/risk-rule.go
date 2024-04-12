package risks

import "github.com/threagile/threagile/pkg/security/types"

type RiskRule interface {
	Category() *types.RiskCategory
	SupportedTags() []string
	GenerateRisks(*types.Model) ([]*types.Risk, error)
}

type RiskRules map[string]RiskRule

func (what RiskRules) Merge(rules RiskRules) RiskRules {
	for key, value := range rules {
		what[key] = value
	}

	return what
}
