package unencrypted_asset

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unencrypted-asset",
		Title: "Unencrypted Technical Assets",
		Description: "Due to the confidentiality rating of the technical asset itself and/or the processed data assets " +
			"this technical asset must be encrypted. The risk rating depends on the sensitivity technical asset itself and of the data assets stored.",
		Impact:     "If this risk is unmitigated, attackers might be able to access unencrypted data when successfully compromising sensitive components.",
		ASVS:       "V6 - Stored Cryptography Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
		Action:     "Encryption of Technical Asset",
		Mitigation: "Apply encryption to the technical asset.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Operations,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "In-scope unencrypted technical assets (excluding " + model.ReverseProxy.String() +
			", " + model.LoadBalancer.String() + ", " + model.WAF.String() + ", " + model.IDS.String() +
			", " + model.IPS.String() + " and embedded components like " + model.Library.String() + ") " +
			"storing data assets rated at least as " + model.Confidential.String() + " or " + model.Critical.String() + ". " +
			"For technical assets storing data assets rated as " + model.StrictlyConfidential.String() + " or " + model.MissionCritical.String() + " the " +
			"encryption must be of type " + model.DataWithEnduserIndividualKey.String() + ".",
		RiskAssessment:             "Depending on the confidentiality rating of the stored data-assets either medium or high risk.",
		FalsePositives:             "When all sensitive data stored within the asset is already fully encrypted on document or data level.",
		ModelFailurePossibleReason: false,
		CWE:                        311,
	}
}

func SupportedTags() []string {
	return []string{}
}

// check for technical assets that should be encrypted due to their confidentiality
func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && !IsEncryptionWaiver(technicalAsset) &&
			(technicalAsset.HighestConfidentiality() >= model.Confidential ||
				technicalAsset.HighestIntegrity() >= model.Critical) {
			verySensitive := technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
				technicalAsset.HighestIntegrity() == model.MissionCritical
			requiresEnduserKey := verySensitive && technicalAsset.Technology.IsUsuallyStoringEnduserData()
			if technicalAsset.Encryption == model.NoneEncryption {
				impact := model.MediumImpact
				if verySensitive {
					impact = model.HighImpact
				}
				risks = append(risks, createRisk(technicalAsset, impact, requiresEnduserKey))
			} else if requiresEnduserKey &&
				(technicalAsset.Encryption == model.Transparent || technicalAsset.Encryption == model.DataWithSymmetricSharedKey || technicalAsset.Encryption == model.DataWithAsymmetricSharedKey) {
				risks = append(risks, createRisk(technicalAsset, model.MediumImpact, requiresEnduserKey))
			}
		}
	}
	return risks
}

// Simple routing assets like 'Reverse Proxy' or 'Load Balancer' usually don't have their own storage and thus have no
// encryption requirement for the asset itself (though for the communication, but that's a different rule)
func IsEncryptionWaiver(asset model.TechnicalAsset) bool {
	return asset.Technology == model.ReverseProxy || asset.Technology == model.LoadBalancer ||
		asset.Technology == model.WAF || asset.Technology == model.IDS || asset.Technology == model.IPS ||
		asset.Technology.IsEmbeddedComponent()
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, requiresEnduserKey bool) model.Risk {
	title := "<b>Unencrypted Technical Asset</b> named <b>" + technicalAsset.Title + "</b>"
	if requiresEnduserKey {
		title += " missing enduser-individual encryption with " + model.DataWithEnduserIndividualKey.String()
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
