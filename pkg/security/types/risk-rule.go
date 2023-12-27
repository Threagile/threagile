package types

type RiskRule struct {
	Category      func() RiskCategory
	SupportedTags func() []string
	GenerateRisks func(input *ParsedModel) []Risk
}
