package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type UncheckedDeploymentRule struct{}

func NewUncheckedDeploymentRule() *UncheckedDeploymentRule {
	return &UncheckedDeploymentRule{}
}

func (*UncheckedDeploymentRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unchecked-deployment",
		Title: "Unchecked Deployment",
		Description: "For each build-pipeline component Unchecked Deployment risks might arise when the build-pipeline " +
			"does not include established DevSecOps best-practices. DevSecOps best-practices scan as part of CI/CD pipelines for " +
			"vulnerabilities in source- or byte-code, dependencies, container layers, and dynamically against running test systems. " +
			"There are several open-source and commercial tools existing in the categories DAST, SAST, and IAST.",
		Impact: "If this risk remains unmitigated, vulnerabilities in custom-developed software or their dependencies " +
			"might not be identified during continuous deployment cycles.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Apply DevSecOps best-practices and use scanning tools to identify vulnerabilities in source- or byte-code," +
			"dependencies, container layers, and optionally also via dynamic scans against running test systems.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Architecture,
		STRIDE:         types.Tampering,
		DetectionLogic: "All development-relevant technical assets.",
		RiskAssessment: "The risk rating depends on the highest rating of the technical assets and data assets processed by deployment-receiving targets.",
		FalsePositives: "When the build-pipeline does not build any software components it can be considered a false positive " +
			"after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1127,
	}
}

func (*UncheckedDeploymentRule) SupportedTags() []string {
	return []string{}
}

func (r *UncheckedDeploymentRule) GenerateRisks(input *types.Model) []*types.Risk {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.Technologies.GetAttribute(types.IsDevelopmentRelevant) {
			risks = append(risks, r.createRisk(input, technicalAsset))
		}
	}
	return risks
}

func (r *UncheckedDeploymentRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Unchecked Deployment</b> risk at <b>" + technicalAsset.Title + "</b>"
	// impact is depending on highest rating
	impact := types.LowImpact
	// data breach at all deployment targets
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, codeDeploymentTargetCommLink := range technicalAsset.CommunicationLinks {
		if codeDeploymentTargetCommLink.Usage == types.DevOps {
			for _, dataAssetID := range codeDeploymentTargetCommLink.DataAssetsSent {
				// it appears to be code when elevated integrity rating of sent data asset
				if input.DataAssets[dataAssetID].Integrity >= types.Important {
					// here we've got a deployment target which has its data assets at risk via deployment of backdoored code
					uniqueDataBreachTechnicalAssetIDs[codeDeploymentTargetCommLink.TargetId] = true
					targetTechAsset := input.TechnicalAssets[codeDeploymentTargetCommLink.TargetId]
					if targetTechAsset.HighestProcessedConfidentiality(input) >= types.Confidential ||
						targetTechAsset.HighestProcessedIntegrity(input) >= types.Critical ||
						targetTechAsset.HighestProcessedAvailability(input) >= types.Critical {
						impact = types.MediumImpact
					}
					break
				}
			}
		}
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	// create risk
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
