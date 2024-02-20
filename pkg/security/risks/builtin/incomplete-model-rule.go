package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type IncompleteModelRule struct{}

func NewIncompleteModelRule() *IncompleteModelRule {
	return &IncompleteModelRule{}
}

func (*IncompleteModelRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "incomplete-model",
		Title: "Incomplete Model",
		Description: "When the threat model contains unknown technologies or transfers data over unknown protocols, this is " +
			"an indicator for an incomplete model.",
		Impact:                     "If this risk is unmitigated, other risks might not be noticed as the model is incomplete.",
		ASVS:                       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
		Action:                     "Threat Modeling Completeness",
		Mitigation:                 "Try to find out what technology or protocol is used instead of specifying that it is unknown.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   types.Architecture,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "All technical assets and communication links with technology type or protocol type specified as unknown.",
		RiskAssessment:             types.LowSeverity.String(),
		FalsePositives:             "Usually no false positives as this looks like an incomplete model.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func (*IncompleteModelRule) SupportedTags() []string {
	return []string{}
}

func (r *IncompleteModelRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.OutOfScope {
			if technicalAsset.Technology == types.UnknownTechnology {
				risks = append(risks, r.createRiskTechAsset(technicalAsset))
			}
			for _, commLink := range technicalAsset.CommunicationLinks {
				if commLink.Protocol == types.UnknownProtocol {
					risks = append(risks, r.createRiskCommLink(technicalAsset, commLink))
				}
			}
		}
	}
	return risks
}

func (r *IncompleteModelRule) createRiskTechAsset(technicalAsset types.TechnicalAsset) types.Risk {
	title := "<b>Unknown Technology</b> specified at technical asset <b>" + technicalAsset.Title + "</b>"
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

func (r *IncompleteModelRule) createRiskCommLink(technicalAsset types.TechnicalAsset, commLink types.CommunicationLink) types.Risk {
	title := "<b>Unknown Protocol</b> specified for communication link <b>" + commLink.Title + "</b> at technical asset <b>" + technicalAsset.Title + "</b>"
	risk := types.Risk{
		CategoryId:                      r.Category().Id,
		Severity:                        types.CalculateSeverity(types.Unlikely, types.LowImpact),
		ExploitationLikelihood:          types.Unlikely,
		ExploitationImpact:              types.LowImpact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: commLink.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + commLink.Id + "@" + technicalAsset.Id
	return risk
}

func (r *IncompleteModelRule) MatchRisk(parsedModel *types.ParsedModel, risk string) bool {
	// todo
	return false
}

func (r *IncompleteModelRule) ExplainRisk(parsedModel *types.ParsedModel, risk string) []string {
	// todo
	return nil
}
