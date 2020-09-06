package path_traversal

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "path-traversal",
		Title: "Path-Traversal",
		Description: "When a filesystem is accessed Path-Traversal or Local-File-Inclusion (LFI) risks might arise. " +
			"The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed or stored.",
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
		Function:       model.Development,
		STRIDE:         model.InformationDisclosure,
		DetectionLogic: "Filesystems accessed by in-scope callers.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data stored inside the technical asset.",
		FalsePositives: "File accesses by filenames not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        22,
	}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.Technology != model.FileServer && technicalAsset.Technology != model.LocalFileSystem {
			continue
		}
		incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			likelihood := model.VeryLikely
			if incomingFlow.Usage == model.DevOps {
				likelihood = model.Likely
			}
			risks = append(risks, createRisk(technicalAsset, incomingFlow, likelihood))
		}
	}
	return risks
}

func SupportedTags() []string {
	return []string{}
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink, likelihood model.RiskExploitationLikelihood) model.Risk {
	caller := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Path-Traversal</b> risk at <b>" + caller.Title + "</b> against filesystem <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.HighImpact
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
