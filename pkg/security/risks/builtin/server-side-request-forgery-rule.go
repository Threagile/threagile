package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type ServerSideRequestForgeryRule struct{}

func NewServerSideRequestForgeryRule() *ServerSideRequestForgeryRule {
	return &ServerSideRequestForgeryRule{}
}

func (*ServerSideRequestForgeryRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "server-side-request-forgery",
		Title: "Server-Side Request Forgery (SSRF)",
		Description: "When a server system (i.e. not a client) is accessing other server systems via typical web protocols " +
			"Server-Side Request Forgery (SSRF) or Local-File-Inclusion (LFI) or Remote-File-Inclusion (RFI) risks might arise. ",
		Impact:     "If this risk is unmitigated, attackers might be able to access sensitive services or files of network-reachable components by modifying outgoing calls of affected components.",
		ASVS:       "V12 - File and Resources Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
		Action:     "SSRF Prevention",
		Mitigation: "Try to avoid constructing the outgoing target URL with caller controllable values. Alternatively use a mapping (whitelist) when accessing outgoing URLs instead of creating them including caller " +
			"controllable values. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.InformationDisclosure,
		DetectionLogic: "In-scope non-client systems accessing (using outgoing communication links) targets with either HTTP or HTTPS protocol.",
		RiskAssessment: "The risk rating (low or medium) depends on the sensitivity of the data assets receivable via web protocols from " +
			"targets within the same network trust-boundary as well on the sensitivity of the data assets receivable via web protocols from the target asset itself. " +
			"Also for cloud-based environments the exploitation impact is at least medium, as cloud backend services can be attacked via SSRF.",
		FalsePositives: "Servers not sending outgoing web requests can be considered " +
			"as false positives after review.",
		ModelFailurePossibleReason: false,
		CWE:                        918,
	}
}

func (*ServerSideRequestForgeryRule) SupportedTags() []string {
	return []string{}
}

func (r *ServerSideRequestForgeryRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technologies.GetAttribute(types.IsClient) || technicalAsset.Technologies.GetAttribute(types.LoadBalancer) {
			continue
		}
		for _, outgoingFlow := range technicalAsset.CommunicationLinks {
			if outgoingFlow.Protocol.IsPotentialWebAccessProtocol() {
				risks = append(risks, r.createRisk(input, technicalAsset, outgoingFlow))
			}
		}
	}
	return risks
}

func (r *ServerSideRequestForgeryRule) createRisk(input *types.ParsedModel, technicalAsset *types.TechnicalAsset, outgoingFlow *types.CommunicationLink) types.Risk {
	target := input.TechnicalAssets[outgoingFlow.TargetId]
	title := "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>" + technicalAsset.Title + "</b> server-side web-requesting " +
		"the target <b>" + target.Title + "</b> via <b>" + outgoingFlow.Title + "</b>"
	impact := types.LowImpact
	// check by the target itself (can be in another trust-boundary)
	if target.HighestProcessedConfidentiality(input) == types.StrictlyConfidential {
		impact = types.MediumImpact
	}
	// check all potential attack targets within the same trust boundary (accessible via web protocols)
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, potentialTargetAsset := range input.TechnicalAssets {
		if technicalAsset.IsSameTrustBoundaryNetworkOnly(input, potentialTargetAsset.Id) {
			for _, commLinkIncoming := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[potentialTargetAsset.Id] {
				if commLinkIncoming.Protocol.IsPotentialWebAccessProtocol() {
					uniqueDataBreachTechnicalAssetIDs[potentialTargetAsset.Id] = true
					if potentialTargetAsset.HighestProcessedConfidentiality(input) == types.StrictlyConfidential {
						impact = types.MediumImpact
					}
				}
			}
		}
	}
	// adjust for cloud-based special risks
	if impact == types.LowImpact && input.TrustBoundaries[technicalAsset.GetTrustBoundaryId(input)].Type.IsWithinCloud() {
		impact = types.MediumImpact
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	likelihood := types.Likely
	if outgoingFlow.Usage == types.DevOps {
		likelihood = types.Unlikely
	}
	risk := types.Risk{
		CategoryId:                      r.Category().Id,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: outgoingFlow.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id + "@" + target.Id + "@" + outgoingFlow.Id
	return risk
}
