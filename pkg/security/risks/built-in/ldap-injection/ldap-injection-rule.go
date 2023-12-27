package ldap_injection

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
		Id:    "ldap-injection",
		Title: "LDAP-Injection",
		Description: "When an LDAP server is accessed LDAP-Injection risks might arise. " +
			"The risk rating depends on the sensitivity of the LDAP server itself and of the data assets processed or stored.",
		Impact:     "If this risk remains unmitigated, attackers might be able to modify LDAP queries and access more data from the LDAP server than allowed.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
		Action:     "LDAP-Injection Prevention",
		Mitigation: "Try to use libraries that properly encode LDAP meta characters in searches and queries to access " +
			"the LDAP sever in order to stay safe from LDAP-Injection vulnerabilities. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope clients accessing LDAP servers via typical LDAP access protocols.",
		RiskAssessment: "The risk rating depends on the sensitivity of the LDAP server itself and of the data assets processed or stored.",
		FalsePositives: "LDAP server queries by search values not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        90,
	}
}

func GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if input.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			if incomingFlow.Protocol == types.LDAP || incomingFlow.Protocol == types.LDAPS {
				likelihood := types.Likely
				if incomingFlow.Usage == types.DevOps {
					likelihood = types.Unlikely
				}
				risks = append(risks, createRisk(input, technicalAsset, incomingFlow, likelihood))
			}
		}
	}
	return risks
}

func SupportedTags() []string {
	return []string{}
}

func createRisk(input *types.ParsedModel, technicalAsset types.TechnicalAsset, incomingFlow types.CommunicationLink, likelihood types.RiskExploitationLikelihood) types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>LDAP-Injection</b> risk at <b>" + caller.Title + "</b> against LDAP server <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := types.MediumImpact
	if technicalAsset.HighestConfidentiality(input) == types.StrictlyConfidential || technicalAsset.HighestIntegrity(input) == types.MissionCritical {
		impact = types.HighImpact
	}
	risk := types.Risk{
		CategoryId:                      Category().Id,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
