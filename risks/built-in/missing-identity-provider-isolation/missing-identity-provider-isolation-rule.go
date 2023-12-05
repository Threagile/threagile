package missing_identity_provider_isolation

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-identity-provider-isolation",
		Title: "Missing Identity Provider Isolation",
		Description: "Highly sensitive identity provider assets and their identity datastores should be isolated from other assets " +
			"by their own network segmentation trust-boundary (" + model.ExecutionEnvironment.String() + " boundaries do not count as network isolation).",
		Impact: "If this risk is unmitigated, attackers successfully attacking other components of the system might have an easy path towards " +
			"highly sensitive identity provider assets and their identity datastores, as they are not separated by network segmentation.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Network Segmentation",
		Mitigation: "Apply a network segmentation trust-boundary around the highly sensitive identity provider assets and their identity datastores.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Operations,
		STRIDE:     model.ElevationOfPrivilege,
		DetectionLogic: "In-scope identity provider assets and their identity datastores " +
			"when surrounded by other (not identity-related) assets (without a network trust-boundary in-between). " +
			"This risk is especially prevalent when other non-identity related assets are within the same execution environment (i.e. same database or same application server).",
		RiskAssessment: "Default is " + model.HighImpact.String() + " impact. The impact is increased to " + model.VeryHighImpact.String() + " when the asset missing the " +
			"trust-boundary protection is rated as " + model.StrictlyConfidential.String() + " or " + model.MissionCritical.String() + ".",
		FalsePositives: "When all assets within the network segmentation trust-boundary are hardened and protected to the same extend as if all were " +
			"identity providers with data of highest sensitivity.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope && technicalAsset.Technology.IsIdentityRelated() {
			moreImpact := technicalAsset.Confidentiality == model.StrictlyConfidential ||
				technicalAsset.Integrity == model.MissionCritical ||
				technicalAsset.Availability == model.MissionCritical
			sameExecutionEnv := false
			createRiskEntry := false
			// now check for any other same-network assets of non-identity-related types
			for sparringAssetCandidateId, _ := range model.ParsedModelRoot.TechnicalAssets { // so inner loop again over all assets
				if technicalAsset.Id != sparringAssetCandidateId {
					sparringAssetCandidate := model.ParsedModelRoot.TechnicalAssets[sparringAssetCandidateId]
					if !sparringAssetCandidate.Technology.IsIdentityRelated() && !sparringAssetCandidate.Technology.IsCloseToHighValueTargetsTolerated() {
						if technicalAsset.IsSameExecutionEnvironment(sparringAssetCandidateId) {
							createRiskEntry = true
							sameExecutionEnv = true
						} else if technicalAsset.IsSameTrustBoundaryNetworkOnly(sparringAssetCandidateId) {
							createRiskEntry = true
						}
					}
				}
			}
			if createRiskEntry {
				risks = append(risks, createRisk(technicalAsset, moreImpact, sameExecutionEnv))
			}
		}
	}
	return risks
}

func createRisk(techAsset model.TechnicalAsset, moreImpact bool, sameExecutionEnv bool) model.Risk {
	impact := model.HighImpact
	likelihood := model.Unlikely
	others := "<b>in the same network segment</b>"
	if moreImpact {
		impact = model.VeryHighImpact
	}
	if sameExecutionEnv {
		likelihood = model.Likely
		others = "<b>in the same execution environment</b>"
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing Identity Provider Isolation</b> to further encapsulate and protect identity-related asset <b>" + techAsset.Title + "</b> against unrelated " +
			"lower protected assets " + others + ", which might be easier to compromise by attackers",
		MostRelevantTechnicalAssetId: techAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{techAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + techAsset.Id
	return risk
}
