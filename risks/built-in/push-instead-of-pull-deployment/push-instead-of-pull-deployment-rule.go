package push_instead_of_pull_deployment

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "push-instead-of-pull-deployment",
		Title: "Push instead of Pull Deployment",
		Description: "When comparing push-based vs. pull-based deployments from a security perspective, pull-based " +
			"deployments improve the overall security of the deployment targets. Every exposed interface of a production system to accept a deployment " +
			"increases the attack surface of the production system, thus a pull-based approach exposes less attack surface relevant " +
			"interfaces.",
		Impact: "If this risk is unmitigated, attackers might have more potential target vectors for attacks, as the overall attack surface is " +
			"unnecessarily increased.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Try to prefer pull-based deployments (like GitOps scenarios offer) over push-based deployments to reduce the attack surface of the production system.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Architecture,
		STRIDE:     model.Tampering,
		DetectionLogic: "Models with build pipeline components accessing in-scope targets of deployment (in a non-readonly way) which " +
			"are not build-related components themselves.",
		RiskAssessment: "The risk rating depends on the highest sensitivity of the deployment targets running custom-developed parts.",
		FalsePositives: "Communication links that are not deployment paths " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        1127,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	impact := model.LowImpact
	for _, buildPipeline := range model.ParsedModelRoot.TechnicalAssets {
		if buildPipeline.Technology == model.BuildPipeline {
			for _, deploymentLink := range buildPipeline.CommunicationLinks {
				targetAsset := model.ParsedModelRoot.TechnicalAssets[deploymentLink.TargetId]
				if !deploymentLink.Readonly && deploymentLink.Usage == model.DevOps &&
					!targetAsset.OutOfScope && !targetAsset.Technology.IsDevelopmentRelevant() && targetAsset.Usage == model.Business {
					if targetAsset.HighestConfidentiality() >= model.Confidential ||
						targetAsset.HighestIntegrity() >= model.Critical ||
						targetAsset.HighestAvailability() >= model.Critical {
						impact = model.MediumImpact
					}
					risks = append(risks, createRisk(buildPipeline, targetAsset, deploymentLink, impact))
				}
			}
		}
	}
	return risks
}

func createRisk(buildPipeline model.TechnicalAsset, deploymentTarget model.TechnicalAsset, deploymentCommLink model.CommunicationLink, impact model.RiskExploitationImpact) model.Risk {
	title := "<b>Push instead of Pull Deployment</b> at <b>" + deploymentTarget.Title + "</b> via build pipeline asset <b>" + buildPipeline.Title + "</b>"
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:          model.Unlikely,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    deploymentTarget.Id,
		MostRelevantCommunicationLinkId: deploymentCommLink.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{deploymentTarget.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + buildPipeline.Id
	return risk
}
