package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type DosRiskyAccessAcrossTrustBoundaryRule struct{}

func NewDosRiskyAccessAcrossTrustBoundaryRule() *DosRiskyAccessAcrossTrustBoundaryRule {
	return &DosRiskyAccessAcrossTrustBoundaryRule{}
}

func (*DosRiskyAccessAcrossTrustBoundaryRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "dos-risky-access-across-trust-boundary",
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
		Function: types.Operations,
		STRIDE:   types.DenialOfService,
		DetectionLogic: "In-scope technical assets (excluding " + types.LoadBalancer + ") with " +
			"availability rating of " + types.Critical.String() + " or higher which have incoming data-flows across a " +
			"network trust-boundary (excluding " + types.DevOps.String() + " usage).",
		RiskAssessment: "Matching technical assets with availability rating " +
			"of " + types.Critical.String() + " or higher are " +
			"at " + types.LowSeverity.String() + " risk. When the availability rating is " +
			types.MissionCritical.String() + " and neither a VPN nor IP filter for the incoming data-flow nor redundancy " +
			"for the asset is applied, the risk-rating is considered " + types.MediumSeverity.String() + ".", // TODO reduce also, when data-flow authenticated and encrypted?
		FalsePositives:             "When the accessed target operations are not time- or resource-consuming.",
		ModelFailurePossibleReason: false,
		CWE:                        400,
	}
}

func (*DosRiskyAccessAcrossTrustBoundaryRule) SupportedTags() []string {
	return []string{}
}

func (r *DosRiskyAccessAcrossTrustBoundaryRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && !technicalAsset.Technologies.GetAttribute(types.LoadBalancer) &&
			technicalAsset.Availability >= types.Critical {
			for _, incomingAccess := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				sourceAsset := input.TechnicalAssets[incomingAccess.SourceId]
				if sourceAsset.Technologies.GetAttribute(types.IsTrafficForwarding) {
					// Now try to walk a call chain up (1 hop only) to find a caller's caller used by human
					callersCommLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[sourceAsset.Id]
					for _, callersCommLink := range callersCommLinks {
						risks = r.checkRisk(input, technicalAsset, callersCommLink, incomingAccess.Id, sourceAsset.Title, risks)
					}
				} else {
					risks = r.checkRisk(input, technicalAsset, incomingAccess, "", "", risks)
				}
			}
		}
	}
	return risks, nil
}

func (r *DosRiskyAccessAcrossTrustBoundaryRule) checkRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingAccess *types.CommunicationLink, linkId string, hopBetween string, risks []*types.Risk) []*types.Risk {
	if !isAcrossTrustBoundaryNetworkOnly(input, incomingAccess) {
		return risks
	}
	if incomingAccess.Usage == types.DevOps {
		return risks
	}
	if incomingAccess.Protocol.IsProcessLocal() {
		return risks
	}

	highRisk := technicalAsset.Availability == types.MissionCritical && !incomingAccess.VPN && !incomingAccess.IpFiltered && !technicalAsset.Redundant
	risks = append(risks, r.createRisk(technicalAsset, incomingAccess, linkId, hopBetween, input.TechnicalAssets[incomingAccess.SourceId], highRisk))
	return risks
}

func (r *DosRiskyAccessAcrossTrustBoundaryRule) createRisk(techAsset *types.TechnicalAsset, dataFlow *types.CommunicationLink, linkId string, hopBetween string,
	clientOutsideTrustBoundary *types.TechnicalAsset, moreRisky bool) *types.Risk {
	impact := types.LowImpact
	if moreRisky {
		impact = types.MediumImpact
	}
	if len(hopBetween) > 0 {
		hopBetween = " forwarded via <b>" + hopBetween + "</b>"
	}
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood: types.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Denial-of-Service</b> risky access of <b>" + techAsset.Title + "</b> by <b>" + clientOutsideTrustBoundary.Title +
			"</b> via <b>" + dataFlow.Title + "</b>" + hopBetween,
		MostRelevantTechnicalAssetId:    techAsset.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + techAsset.Id + "@" + clientOutsideTrustBoundary.Id + "@" + dataFlow.Id
	if dataFlow.Id != linkId {
		risk.SyntheticId += "->" + linkId
	}

	return risk
}
