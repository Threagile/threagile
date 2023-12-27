package missing_network_segmentation

import (
	"sort"

	"github.com/threagile/threagile/pkg/security/types"
)

const raaLimit = 50

func Rule() types.RiskRule {
	return types.RiskRule{
		Category:      Category,
		SupportedTags: SupportedTags,
		GenerateRisks: GenerateRisks,
	}
}

func Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "missing-network-segmentation",
		Title: "Missing Network Segmentation",
		Description: "Highly sensitive assets and/or data stores residing in the same network segment than other " +
			"lower sensitive assets (like webservers or content management systems etc.) should be better protected " +
			"by a network segmentation trust-boundary.",
		Impact: "If this risk is unmitigated, attackers successfully attacking other components of the system might have an easy path towards " +
			"more valuable targets, as they are not separated by network segmentation.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Network Segmentation",
		Mitigation: "Apply a network segmentation trust-boundary around the highly sensitive assets and/or data stores.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   types.Operations,
		STRIDE:     types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets with high sensitivity and RAA values as well as data stores " +
			"when surrounded by assets (without a network trust-boundary in-between) which are of type " + types.ClientSystem.String() + ", " +
			types.WebServer.String() + ", " + types.WebApplication.String() + ", " + types.CMS.String() + ", " + types.WebServiceREST.String() + ", " + types.WebServiceSOAP.String() + ", " +
			types.BuildPipeline.String() + ", " + types.SourcecodeRepository.String() + ", " + types.Monitoring.String() + ", or similar and there is no direct connection between these " +
			"(hence no requirement to be so close to each other).",
		RiskAssessment: "Default is " + types.LowSeverity.String() + " risk. The risk is increased to " + types.MediumSeverity.String() + " when the asset missing the " +
			"trust-boundary protection is rated as " + types.StrictlyConfidential.String() + " or " + types.MissionCritical.String() + ".",
		FalsePositives: "When all assets within the network segmentation trust-boundary are hardened and protected to the same extend as if all were " +
			"containing/processing highly sensitive data.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	keys := make([]string, 0)
	for k := range input.TechnicalAssets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		technicalAsset := input.TechnicalAssets[key]
		if !technicalAsset.OutOfScope && technicalAsset.Technology != types.ReverseProxy && technicalAsset.Technology != types.WAF && technicalAsset.Technology != types.IDS && technicalAsset.Technology != types.IPS && technicalAsset.Technology != types.ServiceRegistry {
			if technicalAsset.RAA >= raaLimit && (technicalAsset.Type == types.Datastore || technicalAsset.Confidentiality >= types.Confidential ||
				technicalAsset.Integrity >= types.Critical || technicalAsset.Availability >= types.Critical) {
				// now check for any other same-network assets of certain types which have no direct connection
				for _, sparringAssetCandidateId := range keys { // so inner loop again over all assets
					if technicalAsset.Id != sparringAssetCandidateId {
						sparringAssetCandidate := input.TechnicalAssets[sparringAssetCandidateId]
						if sparringAssetCandidate.Technology.IsLessProtectedType() &&
							technicalAsset.IsSameTrustBoundaryNetworkOnly(input, sparringAssetCandidateId) &&
							!technicalAsset.HasDirectConnection(input, sparringAssetCandidateId) &&
							!sparringAssetCandidate.Technology.IsCloseToHighValueTargetsTolerated() {
							highRisk := technicalAsset.Confidentiality == types.StrictlyConfidential ||
								technicalAsset.Integrity == types.MissionCritical || technicalAsset.Availability == types.MissionCritical
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

func createRisk(techAsset types.TechnicalAsset, moreRisky bool) types.Risk {
	impact := types.LowImpact
	if moreRisky {
		impact = types.MediumImpact
	}
	risk := types.Risk{
		CategoryId:             Category().Id,
		Severity:               types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood: types.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Missing Network Segmentation</b> to further encapsulate and protect <b>" + techAsset.Title + "</b> against unrelated " +
			"lower protected assets in the same network segment, which might be easier to compromise by attackers",
		MostRelevantTechnicalAssetId: techAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{techAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + techAsset.Id
	return risk
}
