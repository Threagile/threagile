package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type PathTraversalRule struct{}

func NewPathTraversalRule() *PathTraversalRule {
	return &PathTraversalRule{}
}

func (*PathTraversalRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "path-traversal",
		Title: "Path-Traversal",
		Description: "When a filesystem is accessed Path-Traversal or Local-File-Inclusion (LFI) risks might arise. " +
			"The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		Impact: "If this risk is unmitigated, attackers might be able to read sensitive files (configuration data, key/credential files, deployment files, " +
			"business data files, etc.) from the filesystem of affected components.",
		ASVS:       "V12 - File and Resources Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
		Action:     "Path-Traversal Prevention",
		Mitigation: "Before accessing the file cross-check that it resides in the expected folder and is of the expected " +
			"type and filename/suffix. Try to use a mapping if possible instead of directly accessing by a filename which is " +
			"(partly or fully) provided by the caller. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.InformationDisclosure,
		DetectionLogic: "Filesystems accessed by in-scope callers.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data stored inside the technical asset.",
		FalsePositives: "File accesses by filenames not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        22,
	}
}

func (*PathTraversalRule) SupportedTags() []string {
	return []string{}
}

func (r *PathTraversalRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.Technologies.GetAttribute(types.IsFileStorage) {
			continue
		}
		incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if input.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			likelihood := types.VeryLikely
			if incomingFlow.Usage == types.DevOps {
				likelihood = types.Likely
			}
			risks = append(risks, r.createRisk(input, technicalAsset, incomingFlow, likelihood))
		}
	}
	return risks, nil
}

func (r *PathTraversalRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink, likelihood types.RiskExploitationLikelihood) *types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Path-Traversal</b> risk at <b>" + caller.Title + "</b> against filesystem <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := types.MediumImpact
	if technicalAsset.HighestProcessedConfidentiality(input) == types.StrictlyConfidential || technicalAsset.HighestProcessedIntegrity(input) == types.MissionCritical {
		impact = types.HighImpact
	}
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
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
