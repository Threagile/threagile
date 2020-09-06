package unnecessary_communication_link

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unnecessary-communication-link",
		Title: "Unnecessary Communication Link",
		Description: "When a technical communication link does not send or receive any data assets, this is " +
			"an indicator for an unnecessary communication link (or for an incomplete model).",
		Impact:                     "If this risk is unmitigated, attackers might be able to target unnecessary communication links.",
		ASVS:                       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:                     "Attack Surface Reduction",
		Mitigation:                 "Try to avoid using technical communication links that do not send or receive anything.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   model.Architecture,
		STRIDE:                     model.ElevationOfPrivilege,
		DetectionLogic:             "In-scope technical assets' technical communication links not sending or receiving any data assets.",
		RiskAssessment:             model.LowSeverity.String(),
		FalsePositives:             "Usually no false positives as this looks like an incomplete model.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		for _, commLink := range technicalAsset.CommunicationLinks {
			if len(commLink.DataAssetsSent) == 0 && len(commLink.DataAssetsReceived) == 0 {
				if !technicalAsset.OutOfScope || !model.ParsedModelRoot.TechnicalAssets[commLink.TargetId].OutOfScope {
					risks = append(risks, createRisk(technicalAsset, commLink))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, commLink model.CommunicationLink) model.Risk {
	title := "<b>Unnecessary Communication Link</b> titled <b>" + commLink.Title + "</b> at technical asset <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(model.Unlikely, model.LowImpact),
		ExploitationLikelihood:          model.Unlikely,
		ExploitationImpact:              model.LowImpact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: commLink.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + commLink.Id + "@" + technicalAsset.Id
	return risk
}
