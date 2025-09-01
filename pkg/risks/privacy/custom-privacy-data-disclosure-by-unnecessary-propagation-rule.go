package privacy

import (
	"github.com/threagile/threagile/pkg/types"
)

type DataDisclosureByUnnecessaryPropagationRule struct{}

func NewDataDisclosureByUnnecessaryPropagationRule() *DataDisclosureByUnnecessaryPropagationRule {
	return &DataDisclosureByUnnecessaryPropagationRule{}
}

func (*DataDisclosureByUnnecessaryPropagationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "data-disclosure-by-unnecessary-propagation",
		Title:                      "Data Disclosure By Unnecessary Propagation",
		Description:                "When personal data is accessible by or propagated to other assets where it is not needed then Data Disclosure by Unnecessary Propagation privacy risk can arise.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check LINDDUN threat category Data Disclosure (DD.3.2)",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Stop sending personal information to technical assets that do not need it.",
		Mitigation:                 "Scrutinize the need to share personal data, making certain that the technical assets or entities involved truly need access to that information to perform their required function.",
		Check:                      "Are Data Disclosure concerns as described from LINDDUN threat trees (DD.3.2) addressed?",
		Function:                   types.Architecture,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "For each Data Asset received by external-entities, that do not process, store or send it, then generate a threat.",
		RiskAssessment:             "Depends on the type of data assets involved i.e. Personal Information (PI) or not",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*DataDisclosureByUnnecessaryPropagationRule) SupportedTags() []string {
	return []string{"data-disclosure-by-unnecessary-propagation"}
}

func (r *DataDisclosureByUnnecessaryPropagationRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)

	DASentByAllTA := parsedModel.GetMapOfDASentByTechnicalAsset()

	for _, ta := range parsedModel.TechnicalAssets {
		if ta.Type != types.ExternalEntity && !ta.OutOfScope {
			continue
		}
		commLinks := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[ta.Id]
		for _, commLink := range commLinks {
			PIIDs := types.GetPIObjs(parsedModel.DataAssetsSentSorted(commLink))
			DAProcessed := ta.DataAssetsProcessed
			DAStored := ta.DataAssetsStored
			DASentByThisTA := DASentByAllTA[ta.Id]
			for _, piID := range PIIDs {
				_, piSent := DASentByThisTA[piID]
				if !types.Contains(DAProcessed, piID) && !types.Contains(DAStored, piID) && !piSent {
					risks = append(risks, r.createRisk(ta, commLink, piID))
				}
			}
		}
	}
	return risks, nil
}

func (r *DataDisclosureByUnnecessaryPropagationRule) createRisk(technicalAsset *types.TechnicalAsset, link *types.CommunicationLink, piID string) *types.Risk {
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(types.VeryLikely, types.MediumImpact),
		ExploitationLikelihood:          types.VeryLikely,
		ExploitationImpact:              types.MediumImpact,
		Title:                           "<b>Data Disclosure by Unnecessary Propagation</b> risk at <b> " + technicalAsset.Title + "</b> with PI(s): " + piID,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantDataAssetId:         piID,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id + "@" + link.Id + "@" + piID
	return risk
}
