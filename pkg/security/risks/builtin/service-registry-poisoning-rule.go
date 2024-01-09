package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type ServiceRegistryPoisoningRule struct{}

func NewServiceRegistryPoisoningRule() *ServiceRegistryPoisoningRule {
	return &ServiceRegistryPoisoningRule{}
}

func (*ServiceRegistryPoisoningRule) Category() types.RiskCategory {
	return types.RiskCategory{
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
		Function:       types.Architecture,
		STRIDE:         types.Spoofing,
		DetectionLogic: "In-scope service registries.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical assets accessing the service registry " +
			"as well as the data assets processed or stored.",
		FalsePositives: "Service registries not used for service discovery " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        693,
	}
}

func (*ServiceRegistryPoisoningRule) SupportedTags() []string {
	return []string{}
}

func (r *ServiceRegistryPoisoningRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology == types.ServiceRegistry {
			incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			risks = append(risks, r.createRisk(input, technicalAsset, incomingFlows))
		}
	}
	return risks
}

func (r *ServiceRegistryPoisoningRule) createRisk(input *types.ParsedModel, technicalAsset types.TechnicalAsset, incomingFlows []types.CommunicationLink) types.Risk {
	title := "<b>Service Registry Poisoning</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.LowImpact

	for _, incomingFlow := range incomingFlows {
		caller := input.TechnicalAssets[incomingFlow.SourceId]
		if technicalAsset.HighestConfidentiality(input) == types.StrictlyConfidential || technicalAsset.HighestIntegrity(input) == types.MissionCritical || technicalAsset.HighestAvailability(input) == types.MissionCritical ||
			caller.HighestConfidentiality(input) == types.StrictlyConfidential || caller.HighestIntegrity(input) == types.MissionCritical || caller.HighestAvailability(input) == types.MissionCritical ||
			incomingFlow.HighestConfidentiality(input) == types.StrictlyConfidential || incomingFlow.HighestIntegrity(input) == types.MissionCritical || incomingFlow.HighestAvailability(input) == types.MissionCritical {
			impact = types.MediumImpact
			break
		}
	}

	risk := types.Risk{
		CategoryId:                   r.Category().Id,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id}, // TODO: find all service-lookup-using tech assets, which then might use spoofed lookups?
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
