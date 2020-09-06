package unnecessary_data_asset

import (
	"github.com/threagile/threagile/model"
	"sort"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unnecessary-data-asset",
		Title: "Unnecessary Data Asset",
		Description: "When a data asset is not processed or stored by any data assets and also not transferred by any " +
			"communication links, this is an indicator for an unnecessary data asset (or for an incomplete model).",
		Impact: "If this risk is unmitigated, attackers might be able to access unnecessary data assets using " +
			"other vulnerabilities.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Attack Surface Reduction",
		Mitigation: "Try to avoid having data assets that are not required/used.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Architecture,
		STRIDE:     model.ElevationOfPrivilege,
		DetectionLogic: "Modelled data assets not processed or stored by any data assets and also not transferred by any " +
			"communication links.",
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
	// first create them in memory - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	unusedDataAssetIDs := make(map[string]bool)
	for k := range model.ParsedModelRoot.DataAssets {
		unusedDataAssetIDs[k] = true
	}
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		for _, processedDataAssetID := range technicalAsset.DataAssetsProcessed {
			delete(unusedDataAssetIDs, processedDataAssetID)
		}
		for _, storedDataAssetID := range technicalAsset.DataAssetsStored {
			delete(unusedDataAssetIDs, storedDataAssetID)
		}
		for _, commLink := range technicalAsset.CommunicationLinks {
			for _, sentDataAssetID := range commLink.DataAssetsSent {
				delete(unusedDataAssetIDs, sentDataAssetID)
			}
			for _, receivedDataAssetID := range commLink.DataAssetsReceived {
				delete(unusedDataAssetIDs, receivedDataAssetID)
			}
		}
	}
	var keys []string
	for k := range unusedDataAssetIDs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, unusedDataAssetID := range keys {
		risks = append(risks, createRisk(unusedDataAssetID))
	}
	return risks
}

func createRisk(unusedDataAssetID string) model.Risk {
	unusedDataAsset := model.ParsedModelRoot.DataAssets[unusedDataAssetID]
	title := "<b>Unnecessary Data Asset</b> named <b>" + unusedDataAsset.Title + "</b>"
	risk := model.Risk{
		Category:                    Category(),
		Severity:                    model.CalculateSeverity(model.Unlikely, model.LowImpact),
		ExploitationLikelihood:      model.Unlikely,
		ExploitationImpact:          model.LowImpact,
		Title:                       title,
		MostRelevantDataAssetId:     unusedDataAsset.Id,
		DataBreachProbability:       model.Improbable,
		DataBreachTechnicalAssetIDs: []string{unusedDataAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + unusedDataAsset.Id
	return risk
}
