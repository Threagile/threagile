package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type SearchQueryInjectionRule struct{}

func NewSearchQueryInjectionRule() *SearchQueryInjectionRule {
	return &SearchQueryInjectionRule{}
}

func (*SearchQueryInjectionRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "search-query-injection",
		Title: "Search-Query Injection",
		Description: "When a search engine server is accessed Search-Query Injection risks might arise." +
			"<br><br>See for example <a href=\"https://github.com/veracode-research/solr-injection\">https://github.com/veracode-research/solr-injection</a> and " +
			"<a href=\"https://github.com/veracode-research/solr-injection/blob/master/slides/DEFCON-27-Michael-Stepankin-Apache-Solr-Injection.pdf\">https://github.com/veracode-research/solr-injection/blob/master/slides/DEFCON-27-Michael-Stepankin-Apache-Solr-Injection.pdf</a> " +
			"for more details (here related to Solr, but in general showcasing the topic of search query injections).",
		Impact: "If this risk remains unmitigated, attackers might be able to read more data from the search index and " +
			"eventually further escalate towards a deeper system penetration via code executions.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
		Action:     "Search-Query Injection Prevention",
		Mitigation: "Try to use libraries that properly encode search query meta characters in searches and don't expose the " +
			"query unfiltered to the caller. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope clients accessing search engine servers via typical search access protocols.",
		RiskAssessment: "The risk rating depends on the sensitivity of the search engine server itself and of the data assets processed.",
		FalsePositives: "Server engine queries by search values not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        74,
	}
}

func (*SearchQueryInjectionRule) SupportedTags() []string {
	return []string{}
}

func (r *SearchQueryInjectionRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.Technologies.GetAttribute(types.IsSearchRelated) {
			incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, incomingFlow := range incomingFlows {
				if input.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
					continue
				}
				if incomingFlow.Protocol == types.HTTP || incomingFlow.Protocol == types.HTTPS ||
					incomingFlow.Protocol == types.BINARY || incomingFlow.Protocol == types.BinaryEncrypted {
					likelihood := types.VeryLikely
					if incomingFlow.Usage == types.DevOps {
						likelihood = types.Likely
					}
					risks = append(risks, r.createRisk(input, technicalAsset, incomingFlow, likelihood))
				}
			}
		}
	}
	return risks
}

func (r *SearchQueryInjectionRule) createRisk(input *types.ParsedModel, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink, likelihood types.RiskExploitationLikelihood) types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Search Query Injection</b> risk at <b>" + caller.Title + "</b> against search engine server <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := types.MediumImpact
	if technicalAsset.HighestProcessedConfidentiality(input) == types.StrictlyConfidential || technicalAsset.HighestProcessedIntegrity(input) == types.MissionCritical {
		impact = types.HighImpact
	} else if technicalAsset.HighestProcessedConfidentiality(input) <= types.Internal && technicalAsset.HighestProcessedIntegrity(input) == types.Operational {
		impact = types.LowImpact
	}
	risk := types.Risk{
		CategoryId:                      r.Category().Id,
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
