package dos_risky_access_across_trust_boundary

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "dos-risky-access-across-trust-boundary",
		Title: "DoS-risky Access Across Trust-Boundary",
		Description: "Assets accessed across trust boundaries with critical or mission-critical availability rating " +
			"are more prone to Denial-of-Service (DoS) risks.",
		Impact:     "If this risk remains unmitigated, attackers might be able to disturb the availability of important parts of the system.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
		Action:     "Anti-DoS Measures",
		Mitigation: "Apply anti-DoS techniques like throttling and/or per-client load blocking with quotas. " +
			"Also for maintenance access routes consider applying a VPN instead of public reachable interfaces. " +
			"Generally applying redundancy on the targeted technical asset reduces the risk of DoS.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: model.Operations,
		STRIDE:   model.DenialOfService,
		DetectionLogic: "In-scope technical assets (excluding " + model.LoadBalancer.String() + ") with " +
			"availability rating of " + model.Critical.String() + " or higher which have incoming data-flows across a " +
			"network trust-boundary (excluding " + model.DevOps.String() + " usage).",
		RiskAssessment: "Matching technical assets with availability rating " +
			"of " + model.Critical.String() + " or higher are " +
			"at " + model.LowSeverity.String() + " risk. When the availability rating is " +
			model.MissionCritical.String() + " and neither a VPN nor IP filter for the incoming data-flow nor redundancy " +
			"for the asset is applied, the risk-rating is considered " + model.MediumSeverity.String() + ".", // TODO reduce also, when data-flow authenticated and encrypted?
		FalsePositives:             "When the accessed target operations are not time- or resource-consuming.",
		ModelFailurePossibleReason: false,
		CWE:                        400,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology != model.LoadBalancer &&
			technicalAsset.Availability >= model.Critical {
			for _, incomingAccess := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId]
				if sourceAsset.Technology.IsTrafficForwarding() {
					// Now try to walk a call chain up (1 hop only) to find a caller's caller used by human
					callersCommLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[sourceAsset.Id]
					for _, callersCommLink := range callersCommLinks {
						risks = checkRisk(technicalAsset, callersCommLink, sourceAsset.Title, risks)
					}
				} else {
					risks = checkRisk(technicalAsset, incomingAccess, "", risks)
				}
			}
		}
	}
	return risks
}

func checkRisk(technicalAsset model.TechnicalAsset, incomingAccess model.CommunicationLink, hopBetween string, risks []model.Risk) []model.Risk {
	if incomingAccess.IsAcrossTrustBoundaryNetworkOnly() &&
		!incomingAccess.Protocol.IsProcessLocal() && incomingAccess.Usage != model.DevOps {
		highRisk := technicalAsset.Availability == model.MissionCritical &&
			!incomingAccess.VPN && !incomingAccess.IpFiltered && !technicalAsset.Redundant
		risks = append(risks, createRisk(technicalAsset, incomingAccess, hopBetween,
			model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId], highRisk))
	}
	return risks
}

func createRisk(techAsset model.TechnicalAsset, dataFlow model.CommunicationLink, hopBetween string,
	clientOutsideTrustBoundary model.TechnicalAsset, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky {
		impact = model.MediumImpact
	}
	if len(hopBetween) > 0 {
		hopBetween = " forwarded via <b>" + hopBetween + "</b>"
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood: model.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Denial-of-Service</b> risky access of <b>" + techAsset.Title + "</b> by <b>" + clientOutsideTrustBoundary.Title +
			"</b> via <b>" + dataFlow.Title + "</b>" + hopBetween,
		MostRelevantTechnicalAssetId:    techAsset.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + techAsset.Id + "@" + clientOutsideTrustBoundary.Id + "@" + dataFlow.Id
	return risk
}
