package missing_identity_store

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-identity-store",
		Title: "Missing Identity Store",
		Description: "The modeled architecture does not contain an identity store, which might be the risk of a model missing " +
			"critical assets (and thus not seeing their risks).",
		Impact: "If this risk is unmitigated, attackers might be able to exploit risks unseen in this threat model in the identity provider/store " +
			"that is currently missing in the model.",
		ASVS:           "V2 - Authentication Verification Requirements",
		CheatSheet:     "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		Action:         "Identity Store",
		Mitigation:     "Include an identity store in the model if the application has a login.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Architecture,
		STRIDE:         model.Spoofing,
		DetectionLogic: "Models with authenticated data-flows authorized via enduser-identity missing an in-scope identity store.",
		RiskAssessment: "The risk rating depends on the sensitivity of the enduser-identity authorized technical assets and " +
			"their data assets processed and stored.",
		FalsePositives: "Models only offering data/services without any real authentication need " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        287,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope &&
			(technicalAsset.Technology == model.IdentityStoreLDAP || technicalAsset.Technology == model.IdentityStoreDatabase) {
			// everything fine, no risk, as we have an in-scope identity store in the model
			return risks
		}
	}
	// now check if we have enduser-identity authorized communication links, then it's a risk
	riskIdentified := false
	var mostRelevantAsset model.TechnicalAsset
	impact := model.LowImpact
	for _, id := range model.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		for _, commLink := range technicalAsset.CommunicationLinksSorted() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
			if commLink.Authorization == model.EnduserIdentityPropagation {
				riskIdentified = true
				targetAsset := model.ParsedModelRoot.TechnicalAssets[commLink.TargetId]
				if impact == model.LowImpact {
					mostRelevantAsset = targetAsset
					if targetAsset.HighestConfidentiality() >= model.Confidential ||
						targetAsset.HighestIntegrity() >= model.Critical ||
						targetAsset.HighestAvailability() >= model.Critical {
						impact = model.MediumImpact
					}
				}
				if targetAsset.Confidentiality >= model.Confidential ||
					targetAsset.Integrity >= model.Critical ||
					targetAsset.Availability >= model.Critical {
					impact = model.MediumImpact
				}
				// just for referencing the most interesting asset
				if technicalAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
					mostRelevantAsset = technicalAsset
				}
			}
		}
	}
	if riskIdentified {
		risks = append(risks, createRisk(mostRelevantAsset, impact))
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact) model.Risk {
	title := "<b>Missing Identity Store</b> in the threat model (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
