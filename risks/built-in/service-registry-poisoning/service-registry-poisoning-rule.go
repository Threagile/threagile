package service_registry_poisoning

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "service-registry-poisoning",
		Title:       "Service Registry Poisoning",
		Description: "When a service registry used for discovery of trusted service endpoints Service Registry Poisoning risks might arise.",
		Impact: "If this risk remains unmitigated, attackers might be able to poison the service registry with malicious service endpoints or " +
			"malicious lookup and config data leading to breach of sensitive data.",
		ASVS:           "V10 - Malicious Code Verification Requirements",
		CheatSheet:     "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
		Action:         "Service Registry Integrity Check",
		Mitigation:     "Try to strengthen the access control of the service registry and apply cross-checks to detect maliciously poisoned lookup data.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Architecture,
		STRIDE:         model.Spoofing,
		DetectionLogic: "In-scope service registries.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical assets accessing the service registry " +
			"as well as the data assets processed or stored.",
		FalsePositives: "Service registries not used for service discovery " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        693,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology == model.ServiceRegistry {
			incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			risks = append(risks, createRisk(technicalAsset, incomingFlows))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlows []model.CommunicationLink) model.Risk {
	title := "<b>Service Registry Poisoning</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.LowImpact

	for _, incomingFlow := range incomingFlows {
		caller := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
		if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical || technicalAsset.HighestAvailability() == model.MissionCritical ||
			caller.HighestConfidentiality() == model.StrictlyConfidential || caller.HighestIntegrity() == model.MissionCritical || caller.HighestAvailability() == model.MissionCritical ||
			incomingFlow.HighestConfidentiality() == model.StrictlyConfidential || incomingFlow.HighestIntegrity() == model.MissionCritical || incomingFlow.HighestAvailability() == model.MissionCritical {
			impact = model.MediumImpact
			break
		}
	}

	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id}, // TODO: find all service-lookup-using tech assets, which then might use spoofed lookups?
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
