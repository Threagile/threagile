package missing_network_segmentation

import (
	"github.com/threagile/threagile/model"
	"sort"
)

const raaLimit = 50

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-network-segmentation",
		Title: "Missing Network Segmentation",
		Description: "Highly sensitive assets and/or datastores residing in the same network segment than other " +
			"lower sensitive assets (like webservers or content management systems etc.) should be better protected " +
			"by a network segmentation trust-boundary.",
		Impact: "If this risk is unmitigated, attackers successfully attacking other components of the system might have an easy path towards " +
			"more valuable targets, as they are not separated by network segmentation.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Network Segmentation",
		Mitigation: "Apply a network segmentation trust-boundary around the highly sensitive assets and/or datastores.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Operations,
		STRIDE:     model.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets with high sensitivity and RAA values as well as datastores " +
			"when surrounded by assets (without a network trust-boundary in-between) which are of type " + model.ClientSystem.String() + ", " +
			model.WebServer.String() + ", " + model.WebApplication.String() + ", " + model.CMS.String() + ", " + model.WebServiceREST.String() + ", " + model.WebServiceSOAP.String() + ", " +
			model.BuildPipeline.String() + ", " + model.SourcecodeRepository.String() + ", " + model.Monitoring.String() + ", or similar and there is no direct connection between these " +
			"(hence no requirement to be so close to each other).",
		RiskAssessment: "Default is " + model.LowSeverity.String() + " risk. The risk is increased to " + model.MediumSeverity.String() + " when the asset missing the " +
			"trust-boundary protection is rated as " + model.StrictlyConfidential.String() + " or " + model.MissionCritical.String() + ".",
		FalsePositives: "When all assets within the network segmentation trust-boundary are hardened and protected to the same extend as if all were " +
			"containing/processing highly sensitive data.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	keys := make([]string, 0)
	for k, _ := range model.ParsedModelRoot.TechnicalAssets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[key]
		if !technicalAsset.OutOfScope && technicalAsset.Technology != model.ReverseProxy && technicalAsset.Technology != model.WAF && technicalAsset.Technology != model.IDS && technicalAsset.Technology != model.IPS && technicalAsset.Technology != model.ServiceRegistry {
			if technicalAsset.RAA >= raaLimit && (technicalAsset.Type == model.Datastore || technicalAsset.Confidentiality >= model.Confidential ||
				technicalAsset.Integrity >= model.Critical || technicalAsset.Availability >= model.Critical) {
				// now check for any other same-network assets of certain types which have no direct connection
				for _, sparringAssetCandidateId := range keys { // so inner loop again over all assets
					if technicalAsset.Id != sparringAssetCandidateId {
						sparringAssetCandidate := model.ParsedModelRoot.TechnicalAssets[sparringAssetCandidateId]
						if sparringAssetCandidate.Technology.IsLessProtectedType() &&
							technicalAsset.IsSameTrustBoundaryNetworkOnly(sparringAssetCandidateId) &&
							!technicalAsset.HasDirectConnection(sparringAssetCandidateId) &&
							!sparringAssetCandidate.Technology.IsCloseToHighValueTargetsTolerated() {
							highRisk := technicalAsset.Confidentiality == model.StrictlyConfidential ||
								technicalAsset.Integrity == model.MissionCritical || technicalAsset.Availability == model.MissionCritical
							risks = append(risks, createRisk(technicalAsset, highRisk))
							break
						}
					}
				}
			}
		}
	}
	return risks
}

func createRisk(techAsset model.TechnicalAsset, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood: model.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Missing Network Segmentation</b> to further encapsulate and protect <b>" + techAsset.Title + "</b> against unrelated " +
			"lower protected assets in the same network segment, which might be easier to compromise by attackers",
		MostRelevantTechnicalAssetId: techAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{techAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + techAsset.Id
	return risk
}
