package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type MissingIdentityStoreRule struct{}

func NewMissingIdentityStoreRule() *MissingIdentityStoreRule {
	return &MissingIdentityStoreRule{}
}

func (*MissingIdentityStoreRule) Category() types.RiskCategory {
	return types.RiskCategory{
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
		Function:       types.Architecture,
		STRIDE:         types.Spoofing,
		DetectionLogic: "Models with authenticated data-flows authorized via end user identity missing an in-scope identity store.",
		RiskAssessment: "The risk rating depends on the sensitivity of the end user-identity authorized technical assets and " +
			"their data assets processed and stored.",
		FalsePositives: "Models only offering data/services without any real authentication need " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        287,
	}
}

func (*MissingIdentityStoreRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingIdentityStoreRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if !technicalAsset.OutOfScope &&
			(technicalAsset.Technology == types.IdentityStoreLDAP || technicalAsset.Technology == types.IdentityStoreDatabase) {
			// everything fine, no risk, as we have an in-scope identity store in the model
			return risks
		}
	}
	// now check if we have end user identity authorized communication links, then it's a risk
	riskIdentified := false
	var mostRelevantAsset types.TechnicalAsset
	impact := types.LowImpact
	for _, id := range input.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with the highest sensitivity as example asset
		technicalAsset := input.TechnicalAssets[id]
		for _, commLink := range technicalAsset.CommunicationLinksSorted() { // use the sorted one to always get the same tech asset with the highest sensitivity as example asset
			if commLink.Authorization == types.EndUserIdentityPropagation {
				riskIdentified = true
				targetAsset := input.TechnicalAssets[commLink.TargetId]
				if impact == types.LowImpact {
					mostRelevantAsset = targetAsset
					if targetAsset.HighestConfidentiality(input) >= types.Confidential ||
						targetAsset.HighestIntegrity(input) >= types.Critical ||
						targetAsset.HighestAvailability(input) >= types.Critical {
						impact = types.MediumImpact
					}
				}
				if targetAsset.Confidentiality >= types.Confidential ||
					targetAsset.Integrity >= types.Critical ||
					targetAsset.Availability >= types.Critical {
					impact = types.MediumImpact
				}
				// just for referencing the most interesting asset
				if technicalAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
					mostRelevantAsset = technicalAsset
				}
			}
		}
	}
	if riskIdentified {
		risks = append(risks, r.createRisk(mostRelevantAsset, impact))
	}
	return risks
}

func (r *MissingIdentityStoreRule) createRisk(technicalAsset types.TechnicalAsset, impact types.RiskExploitationImpact) types.Risk {
	title := "<b>Missing Identity Store</b> in the threat model (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
	risk := types.Risk{
		CategoryId:                   r.Category().Id,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
