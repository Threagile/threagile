package missing_waf

import (
	"github.com/threagile/threagile/pkg/security/types"
)

func Rule() types.RiskRule {
	return types.RiskRule{
		Category:      Category,
		SupportedTags: SupportedTags,
		GenerateRisks: GenerateRisks,
	}
}

func Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "missing-waf",
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
		Check:          "Is a Web Application Firewall (WAF) in place?",
		Function:       types.Operations,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope web-services and/or web-applications accessed across a network trust boundary not having a Web Application Firewall (WAF) in front of them.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed and stored.",
		FalsePositives: "Targets only accessible via WAFs or reverse proxies containing a WAF component (like ModSecurity) can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if !technicalAsset.OutOfScope &&
			(technicalAsset.Technology.IsWebApplication() || technicalAsset.Technology.IsWebService()) {
			for _, incomingAccess := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				if incomingAccess.IsAcrossTrustBoundaryNetworkOnly(input) &&
					incomingAccess.Protocol.IsPotentialWebAccessProtocol() &&
					input.TechnicalAssets[incomingAccess.SourceId].Technology != types.WAF {
					risks = append(risks, createRisk(input, technicalAsset))
					break
				}
			}
		}
	}
	return risks
}

func createRisk(input *types.ParsedModel, technicalAsset types.TechnicalAsset) types.Risk {
	title := "<b>Missing Web Application Firewall (WAF)</b> risk at <b>" + technicalAsset.Title + "</b>"
	likelihood := types.Unlikely
	impact := types.LowImpact
	if technicalAsset.HighestConfidentiality(input) == types.StrictlyConfidential ||
		technicalAsset.HighestIntegrity(input) == types.MissionCritical ||
		technicalAsset.HighestAvailability(input) == types.MissionCritical {
		impact = types.MediumImpact
	}
	risk := types.Risk{
		CategoryId:                   Category().Id,
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
