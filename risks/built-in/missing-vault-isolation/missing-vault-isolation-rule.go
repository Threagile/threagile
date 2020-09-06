package missing_vault_isolation

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-vault-isolation",
		Title: "Missing Vault Isolation",
		Description: "Highly sensitive vault assets and their datastores should be isolated from other assets " +
			"by their own network segmentation trust-boundary (" + model.ExecutionEnvironment.String() + " boundaries do not count as network isolation).",
		Impact: "If this risk is unmitigated, attackers successfully attacking other components of the system might have an easy path towards " +
			"highly sensitive vault assets and their datastores, as they are not separated by network segmentation.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Network Segmentation",
		Mitigation: "Apply a network segmentation trust-boundary around the highly sensitive vault assets and their datastores.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Operations,
		STRIDE:     model.ElevationOfPrivilege,
		DetectionLogic: "In-scope vault assets " +
			"when surrounded by other (not vault-related) assets (without a network trust-boundary in-between). " +
			"This risk is especially prevalent when other non-vault related assets are within the same execution environment (i.e. same database or same application server).",
		RiskAssessment: "Default is " + model.MediumImpact.String() + " impact. The impact is increased to " + model.HighImpact.String() + " when the asset missing the " +
			"trust-boundary protection is rated as " + model.StrictlyConfidential.String() + " or " + model.MissionCritical.String() + ".",
		FalsePositives: "When all assets within the network segmentation trust-boundary are hardened and protected to the same extend as if all were " +
			"vaults with data of highest sensitivity.",
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
		if !technicalAsset.OutOfScope && technicalAsset.Technology == model.Vault {
			moreImpact := technicalAsset.Confidentiality == model.StrictlyConfidential ||
				technicalAsset.Integrity == model.MissionCritical ||
				technicalAsset.Availability == model.MissionCritical
			sameExecutionEnv := false
			createRiskEntry := false
			// now check for any other same-network assets of non-vault-related types
			for sparringAssetCandidateId, _ := range model.ParsedModelRoot.TechnicalAssets { // so inner loop again over all assets
				if technicalAsset.Id != sparringAssetCandidateId {
					sparringAssetCandidate := model.ParsedModelRoot.TechnicalAssets[sparringAssetCandidateId]
					if sparringAssetCandidate.Technology != model.Vault && !isVaultStorage(technicalAsset, sparringAssetCandidate) {
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

func isVaultStorage(vault model.TechnicalAsset, storage model.TechnicalAsset) bool {
	return storage.Type == model.Datastore && vault.HasDirectConnection(storage.Id)
}

func createRisk(techAsset model.TechnicalAsset, moreImpact bool, sameExecutionEnv bool) model.Risk {
	impact := model.MediumImpact
	likelihood := model.Unlikely
	others := "<b>in the same network segment</b>"
	if moreImpact {
		impact = model.HighImpact
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
		Title: "<b>Missing Vault Isolation</b> to further encapsulate and protect vault-related asset <b>" + techAsset.Title + "</b> against unrelated " +
			"lower protected assets " + others + ", which might be easier to compromise by attackers",
		MostRelevantTechnicalAssetId: techAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{techAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + techAsset.Id
	return risk
}
