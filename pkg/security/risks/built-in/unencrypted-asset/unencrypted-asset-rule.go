package unencrypted_asset

import (
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/types"
)

func Rule() model.CustomRiskRule {
	return model.CustomRiskRule{
		Category:      Category,
		SupportedTags: SupportedTags,
		GenerateRisks: GenerateRisks,
	}
}

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
		Function:   types.Operations,
		STRIDE:     types.InformationDisclosure,
		DetectionLogic: "In-scope unencrypted technical assets (excluding " + types.ReverseProxy.String() +
			", " + types.LoadBalancer.String() + ", " + types.WAF.String() + ", " + types.IDS.String() +
			", " + types.IPS.String() + " and embedded components like " + types.Library.String() + ") " +
			"storing data assets rated at least as " + types.Confidential.String() + " or " + types.Critical.String() + ". " +
			"For technical assets storing data assets rated as " + types.StrictlyConfidential.String() + " or " + types.MissionCritical.String() + " the " +
			"encryption must be of type " + types.DataWithEndUserIndividualKey.String() + ".",
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

func GenerateRisks(input *model.ParsedModel) []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && !IsEncryptionWaiver(technicalAsset) &&
			(technicalAsset.HighestConfidentiality(input) >= types.Confidential ||
				technicalAsset.HighestIntegrity(input) >= types.Critical) {
			verySensitive := technicalAsset.HighestConfidentiality(input) == types.StrictlyConfidential ||
				technicalAsset.HighestIntegrity(input) == types.MissionCritical
			requiresEndUserKey := verySensitive && technicalAsset.Technology.IsUsuallyStoringEndUserData()
			if technicalAsset.Encryption == types.NoneEncryption {
				impact := types.MediumImpact
				if verySensitive {
					impact = types.HighImpact
				}
				risks = append(risks, createRisk(technicalAsset, impact, requiresEndUserKey))
			} else if requiresEndUserKey &&
				(technicalAsset.Encryption == types.Transparent || technicalAsset.Encryption == types.DataWithSymmetricSharedKey || technicalAsset.Encryption == types.DataWithAsymmetricSharedKey) {
				risks = append(risks, createRisk(technicalAsset, types.MediumImpact, requiresEndUserKey))
			}
		}
	}
	return risks
}

// Simple routing assets like 'Reverse Proxy' or 'Load Balancer' usually don't have their own storage and thus have no
// encryption requirement for the asset itself (though for the communication, but that's a different rule)

func IsEncryptionWaiver(asset model.TechnicalAsset) bool {
	return asset.Technology == types.ReverseProxy || asset.Technology == types.LoadBalancer ||
		asset.Technology == types.WAF || asset.Technology == types.IDS || asset.Technology == types.IPS ||
		asset.Technology.IsEmbeddedComponent()
}

func createRisk(technicalAsset model.TechnicalAsset, impact types.RiskExploitationImpact, requiresEndUserKey bool) model.Risk {
	title := "<b>Unencrypted Technical Asset</b> named <b>" + technicalAsset.Title + "</b>"
	if requiresEndUserKey {
		title += " missing end user individual encryption with " + types.DataWithEndUserIndividualKey.String()
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
