package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type UnnecessaryTechnicalAssetRule struct{}

func NewUnnecessaryTechnicalAssetRule() *UnnecessaryTechnicalAssetRule {
	return &UnnecessaryTechnicalAssetRule{}
}

func (*UnnecessaryTechnicalAssetRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "unnecessary-technical-asset",
		Title: "Unnecessary Technical Asset",
		Description: "When a technical asset does not process any data assets, this is " +
			"an indicator for an unnecessary technical asset (or for an incomplete model). " +
			"This is also the case if the asset has no communication links (either outgoing or incoming).",
		Impact:                     "If this risk is unmitigated, attackers might be able to target unnecessary technical assets.",
		ASVS:                       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:                     "Attack Surface Reduction",
		Mitigation:                 "Try to avoid using technical assets that do not process or store anything.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   types.Architecture,
		STRIDE:                     types.ElevationOfPrivilege,
		DetectionLogic:             "Technical assets not processing or storing any data assets.",
		RiskAssessment:             types.LowSeverity.String(),
		FalsePositives:             "Usually no false positives as this looks like an incomplete model.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func (*UnnecessaryTechnicalAssetRule) SupportedTags() []string {
	return []string{}
}

func (r *UnnecessaryTechnicalAssetRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if len(technicalAsset.DataAssetsProcessed) == 0 && len(technicalAsset.DataAssetsStored) == 0 ||
			(len(technicalAsset.CommunicationLinks) == 0 && len(input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]) == 0) {
			risks = append(risks, r.createRisk(technicalAsset))
		}
	}
	return risks
}

func (r *UnnecessaryTechnicalAssetRule) createRisk(technicalAsset types.TechnicalAsset) types.Risk {
	title := "<b>Unnecessary Technical Asset</b> named <b>" + technicalAsset.Title + "</b>"
	risk := types.Risk{
		CategoryId:                   r.Category().Id,
		Severity:                     types.CalculateSeverity(types.Unlikely, types.LowImpact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           types.LowImpact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

func (r *UnnecessaryTechnicalAssetRule) MatchRisk(parsedModel *types.ParsedModel, risk string) bool {
	// todo
	return false
}

func (r *UnnecessaryTechnicalAssetRule) ExplainRisk(parsedModel *types.ParsedModel, risk string) []string {
	// todo
	return nil
}
