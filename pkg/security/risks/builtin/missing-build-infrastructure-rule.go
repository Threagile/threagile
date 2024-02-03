package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type MissingBuildInfrastructureRule struct{}

func NewMissingBuildInfrastructureRule() *MissingBuildInfrastructureRule {
	return &MissingBuildInfrastructureRule{}
}

func (*MissingBuildInfrastructureRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "missing-build-infrastructure",
		Title: "Missing Build Infrastructure",
		Description: "The modeled architecture does not contain a build infrastructure (devops-client, sourcecode-repo, build-pipeline, etc.), " +
			"which might be the risk of a model missing critical assets (and thus not seeing their risks). " +
			"If the architecture contains custom-developed parts, the pipeline where code gets developed " +
			"and built needs to be part of the model.",
		Impact: "If this risk is unmitigated, attackers might be able to exploit risks unseen in this threat model due to " +
			"critical build infrastructure components missing in the model.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Include the build infrastructure in the model.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   types.Architecture,
		STRIDE:     types.Tampering,
		DetectionLogic: "Models with in-scope custom-developed parts missing in-scope development (code creation) and build infrastructure " +
			"components (devops-client, sourcecode-repo, build-pipeline, etc.).",
		RiskAssessment: "The risk rating depends on the highest sensitivity of the in-scope assets running custom-developed parts.",
		FalsePositives: "Models not having any custom-developed parts " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        1127,
	}
}

func (*MissingBuildInfrastructureRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingBuildInfrastructureRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	hasCustomDevelopedParts, hasBuildPipeline, hasSourcecodeRepo, hasDevOpsClient := false, false, false, false
	impact := types.LowImpact
	var mostRelevantAsset types.TechnicalAsset
	for _, id := range input.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with the highest sensitivity as example asset
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.CustomDevelopedParts && !technicalAsset.OutOfScope {
			hasCustomDevelopedParts = true
			if impact == types.LowImpact {
				mostRelevantAsset = technicalAsset
				if technicalAsset.HighestConfidentiality(input) >= types.Confidential ||
					technicalAsset.HighestIntegrity(input) >= types.Critical ||
					technicalAsset.HighestAvailability(input) >= types.Critical {
					impact = types.MediumImpact
				}
			}
			if technicalAsset.Confidentiality >= types.Confidential ||
				technicalAsset.Integrity >= types.Critical ||
				technicalAsset.Availability >= types.Critical {
				impact = types.MediumImpact
			}
			// just for referencing the most interesting asset
			if technicalAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
				mostRelevantAsset = technicalAsset
			}
		}
		if technicalAsset.Technology == types.BuildPipeline {
			hasBuildPipeline = true
		}
		if technicalAsset.Technology == types.SourcecodeRepository {
			hasSourcecodeRepo = true
		}
		if technicalAsset.Technology == types.DevOpsClient {
			hasDevOpsClient = true
		}
	}
	hasBuildInfrastructure := hasBuildPipeline && hasSourcecodeRepo && hasDevOpsClient
	if hasCustomDevelopedParts && !hasBuildInfrastructure {
		risks = append(risks, r.createRisk(mostRelevantAsset, impact))
	}
	return risks
}

func (r *MissingBuildInfrastructureRule) createRisk(technicalAsset types.TechnicalAsset, impact types.RiskExploitationImpact) types.Risk {
	title := "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
	risk := types.Risk{
		CategoryId:                   r.Category().Id,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
