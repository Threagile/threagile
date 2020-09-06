package unnecessary_technical_asset

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unnecessary-technical-asset",
		Title: "Unnecessary Technical Asset",
		Description: "When a technical asset does not process or store any data assets, this is " +
			"an indicator for an unnecessary technical asset (or for an incomplete model). " +
			"This is also the case if the asset has no communication links (either outgoing or incoming).",
		Impact:                     "If this risk is unmitigated, attackers might be able to target unnecessary technical assets.",
		ASVS:                       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:                     "Attack Surface Reduction",
		Mitigation:                 "Try to avoid using technical assets that do not process or store anything.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   model.Architecture,
		STRIDE:                     model.ElevationOfPrivilege,
		DetectionLogic:             "Technical assets not processing or storing any data assets.",
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
		if len(technicalAsset.DataAssetsProcessed) == 0 && len(technicalAsset.DataAssetsStored) == 0 ||
			(len(technicalAsset.CommunicationLinks) == 0 && len(model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]) == 0) {
			risks = append(risks, createRisk(technicalAsset))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Unnecessary Technical Asset</b> named <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, model.LowImpact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           model.LowImpact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
