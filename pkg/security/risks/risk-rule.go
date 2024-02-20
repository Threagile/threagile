package risks

import "github.com/threagile/threagile/pkg/security/types"

type RiskRule interface {
	Category() types.RiskCategory
	SupportedTags() []string
	GenerateRisks(*types.ParsedModel) []types.Risk
	MatchRisk(parsedModel *types.ParsedModel, risk string) bool
	ExplainRisk(parsedModel *types.ParsedModel, risk string) []string
}
