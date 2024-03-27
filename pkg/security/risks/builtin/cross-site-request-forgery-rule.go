package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type CrossSiteRequestForgeryRule struct{}

func NewCrossSiteRequestForgeryRule() *CrossSiteRequestForgeryRule {
	return &CrossSiteRequestForgeryRule{}
}

func (*CrossSiteRequestForgeryRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:          "cross-site-request-forgery",
		Title:       "Cross-Site Request Forgery (CSRF)",
		Description: "When a web application is accessed via web protocols Cross-Site Request Forgery (CSRF) risks might arise.",
		Impact: "If this risk remains unmitigated, attackers might be able to trick logged-in victim users into unwanted actions within the web application " +
			"by visiting an attacker controlled web site.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
		Action:     "CSRF Prevention",
		Mitigation: "Try to use anti-CSRF tokens ot the double-submit patterns (at least for logged-in requests). " +
			"When your authentication scheme depends on cookies (like session or token cookies), consider marking them with " +
			"the same-site flag. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Spoofing,
		DetectionLogic: "In-scope web applications accessed via typical web access protocols.",
		RiskAssessment: "The risk rating depends on the integrity rating of the data sent across the communication link.",
		FalsePositives: "Web applications passing the authentication sate via custom headers instead of cookies can " +
			"eventually be false positives. Also when the web application " +
			"is not accessed via a browser-like component (i.e not by a human user initiating the request that " +
			"gets passed through all components until it reaches the web application) this can be considered a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        352,
	}
}

func (*CrossSiteRequestForgeryRule) SupportedTags() []string {
	return []string{}
}

func (r *CrossSiteRequestForgeryRule) GenerateRisks(parsedModel *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.WebApplication) {
			continue
		}
		incomingFlows := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if incomingFlow.Protocol.IsPotentialWebAccessProtocol() {
				likelihood := types.VeryLikely
				if incomingFlow.Usage == types.DevOps {
					likelihood = types.Likely
				}
				risks = append(risks, r.createRisk(parsedModel, technicalAsset, incomingFlow, likelihood))
			}
		}
	}
	return risks
}

func (r *CrossSiteRequestForgeryRule) createRisk(parsedModel *types.ParsedModel, technicalAsset types.TechnicalAsset, incomingFlow types.CommunicationLink, likelihood types.RiskExploitationLikelihood) types.Risk {
	sourceAsset := parsedModel.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>" + technicalAsset.Title + "</b> via <b>" + incomingFlow.Title + "</b> from <b>" + sourceAsset.Title + "</b>"
	impact := types.LowImpact
	if incomingFlow.HighestIntegrity(parsedModel) == types.MissionCritical {
		impact = types.MediumImpact
	}
	risk := types.Risk{
		CategoryId:                      r.Category().Id,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
