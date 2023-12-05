package search_query_injection

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
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
		Function:       model.Development,
		STRIDE:         model.Tampering,
		DetectionLogic: "In-scope clients accessing search engine servers via typical search access protocols.",
		RiskAssessment: "The risk rating depends on the sensitivity of the search engine server itself and of the data assets processed or stored.",
		FalsePositives: "Server engine queries by search values not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        74,
	}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.Technology == model.SearchEngine || technicalAsset.Technology == model.SearchIndex {
			incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, incomingFlow := range incomingFlows {
				if model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
					continue
				}
				if incomingFlow.Protocol == model.HTTP || incomingFlow.Protocol == model.HTTPS ||
					incomingFlow.Protocol == model.BINARY || incomingFlow.Protocol == model.BINARY_encrypted {
					likelihood := model.VeryLikely
					if incomingFlow.Usage == model.DevOps {
						likelihood = model.Likely
					}
					risks = append(risks, createRisk(technicalAsset, incomingFlow, likelihood))
				}
			}
		}
	}
	return risks
}

func SupportedTags() []string {
	return []string{}
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink, likelihood model.RiskExploitationLikelihood) model.Risk {
	caller := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Search Query Injection</b> risk at <b>" + caller.Title + "</b> against search engine server <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.HighImpact
	} else if technicalAsset.HighestConfidentiality() <= model.Internal && technicalAsset.HighestIntegrity() == model.Operational {
		impact = model.LowImpact
	}
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           model.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
