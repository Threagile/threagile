package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingWafRule struct{}

func NewMissingWafRule() *MissingWafRule {
	return &MissingWafRule{}
}

func (*MissingWafRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-waf",
		Title: "Missing Web Application Firewall (WAF)",
		Description: "To have a first line of filtering defense, security architectures with web-services or web-applications should include a WAF in front of them. " +
			"Even though a WAF is not a replacement for security (all components must be secure even without a WAF) it adds another layer of defense to the overall " +
			"system by delaying some attacks and having easier attack alerting through it.",
		Impact:     "If this risk is unmitigated, attackers might be able to apply standard attack pattern tests at great speed without any filtering.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html",
		Action:     "Web Application Firewall (WAF)",
		Mitigation: "Consider placing a Web Application Firewall (WAF) in front of the web-services and/or web-applications. For cloud environments many cloud providers offer " +
			"pre-configured WAFs. Even reverse proxies can be enhances by a WAF component via ModSecurity plugins.",
		Check:          "GetAttribute a Web Application Firewall (WAF) in place?",
		Function:       types.Operations,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope web-services and/or web-applications accessed across a network trust boundary not having a Web Application Firewall (WAF) in front of them.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Targets only accessible via WAFs or reverse proxies containing a WAF component (like ModSecurity) can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func (*MissingWafRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingWafRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope {
			continue
		}
		if !technicalAsset.Technologies.GetAttribute(types.WebApplication) &&
			!technicalAsset.Technologies.GetAttribute(types.IsWebService) {
			continue
		}
		for _, incomingAccess := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			if isAcrossTrustBoundaryNetworkOnly(input, incomingAccess) &&
				incomingAccess.Protocol.IsPotentialWebAccessProtocol() &&
				!input.TechnicalAssets[incomingAccess.SourceId].Technologies.GetAttribute(types.WAF) {
				risks = append(risks, r.createRisk(input, technicalAsset))
				break
			}
		}
	}
	return risks, nil
}

func (r *MissingWafRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Missing Web Application Firewall (WAF)</b> risk at <b>" + technicalAsset.Title + "</b>"
	likelihood := types.Unlikely
	impact := types.LowImpact
	if technicalAsset.HighestProcessedConfidentiality(input) == types.StrictlyConfidential ||
		technicalAsset.HighestProcessedIntegrity(input) == types.MissionCritical ||
		technicalAsset.HighestProcessedAvailability(input) == types.MissionCritical {
		impact = types.MediumImpact
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
