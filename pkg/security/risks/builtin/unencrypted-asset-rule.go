package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type UnencryptedAssetRule struct{}

func NewUnencryptedAssetRule() *UnencryptedAssetRule {
	return &UnencryptedAssetRule{}
}

func (*UnencryptedAssetRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "unencrypted-asset",
		Title: "Unencrypted Technical Assets",
		Description: "Due to the confidentiality rating of the technical asset itself and/or the stored data assets " +
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
		// NOTE: the risk assessment does not only consider the CIs of the *stored* data-assets
		RiskAssessment:             "Depending on the confidentiality rating of the stored data-assets either medium or high risk.",
		FalsePositives:             "When all sensitive data stored within the asset is already fully encrypted on document or data level.",
		ModelFailurePossibleReason: false,
		CWE:                        311,
	}
}

func (*UnencryptedAssetRule) SupportedTags() []string {
	return []string{}
}

// check for technical assets that should be encrypted due to their confidentiality

func (r *UnencryptedAssetRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && !isEncryptionWaiver(technicalAsset) && len(technicalAsset.DataAssetsStored) > 0 &&
			(technicalAsset.HighestStoredConfidentiality(input) >= types.Confidential ||
				technicalAsset.HighestStoredIntegrity(input) >= types.Critical) {
			verySensitive := technicalAsset.HighestStoredConfidentiality(input) == types.StrictlyConfidential ||
				technicalAsset.HighestStoredIntegrity(input) == types.MissionCritical
			requiresEndUserKey := verySensitive && technicalAsset.Technologies.IsUsuallyStoringEndUserData()
			if technicalAsset.Encryption == types.NoneEncryption {
				impact := types.MediumImpact
				if verySensitive {
					impact = types.HighImpact
				}
				risks = append(risks, r.createRisk(technicalAsset, impact, requiresEndUserKey))
			} else if requiresEndUserKey &&
				(technicalAsset.Encryption == types.Transparent || technicalAsset.Encryption == types.DataWithSymmetricSharedKey || technicalAsset.Encryption == types.DataWithAsymmetricSharedKey) {
				risks = append(risks, r.createRisk(technicalAsset, types.MediumImpact, requiresEndUserKey))
			}
		}
	}
	return risks
}

// Simple routing assets like 'Reverse Proxy' or 'Load Balancer' usually don't have their own storage and thus have no
// encryption requirement for the asset itself (though for the communication, but that's a different rule)

func isEncryptionWaiver(asset types.TechnicalAsset) bool {
	return asset.Technologies.HasAnyType(types.ReverseProxy, types.LoadBalancer, types.WAF, types.IDS, types.IPS) || asset.Technologies.IsEmbeddedComponent()
}

func (r *UnencryptedAssetRule) createRisk(technicalAsset types.TechnicalAsset, impact types.RiskExploitationImpact, requiresEndUserKey bool) types.Risk {
	title := "<b>Unencrypted Technical Asset</b> named <b>" + technicalAsset.Title + "</b>"
	if requiresEndUserKey {
		title += " missing end user individual encryption with " + types.DataWithEndUserIndividualKey.String()
	}
	risk := types.Risk{
		CategoryId:                   r.Category().Id,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
