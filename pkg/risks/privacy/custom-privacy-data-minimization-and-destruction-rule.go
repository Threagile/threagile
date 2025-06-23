package privacy

import (
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

type DataMinimizationAndDestructionRule struct{}

func NewDataMinimizationAndDestructionRule() *DataMinimizationAndDestructionRule {
	return &DataMinimizationAndDestructionRule{}
}

func (*DataMinimizationAndDestructionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "data-minimization-and-destruction",
		Title:                      "Data Minimization and Destruction",
		Description:                "Data Minimization and Destruction risk can arise when more personal information (PI) is sent to an asset than is required for the functioning of that asset. E.g. a non-storage component receives the PI data that it does not send or a storage component that receives PI but neither stores nor sends it.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check NIST Privacy Controls Framework",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Implement data minimization principles.",
		Mitigation:                 "Review whether all the data is strictly necessary for the system's functionality.",
		Check:                      "Are Data Disclosure concerns as described from LINDDUN threat trees (DD.1.1) addressed?",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Rule identifies risks where personal data (PI) is: (1) Received but not sent or stored, (2) Received but neither sent nor stored in persistent storage.",
		RiskAssessment:             "The risk rating depends on sufficient access control mechanisms of inbound access request.",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (r DataMinimizationAndDestructionRule) SupportedTags() []string {
	return []string{"data-minimization-and-destruction"}
}

func getPIDataAssetIDs(m map[string]bool) []string {
	PIDataAssetIDs := make([]string, 0)
	for k, v := range m {
		if v {
			PIDataAssetIDs = append(PIDataAssetIDs, k)
		}
	}
	return PIDataAssetIDs
}

func (r *DataMinimizationAndDestructionRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)

	if parsedModel.Deidentified {
		return risks, nil
	}

	daSentMap := parsedModel.GetMapOfDASentByTechnicalAsset()
	daRecdMap := parsedModel.GetDARecvd()
	for _, ta := range parsedModel.TechnicalAssets {
		daSent := getPIDataAssetIDs(daSentMap[ta.Id])
		daRecd := getPIDataAssetIDs(daRecdMap[ta.Id])
		daStored := parsedModel.GetPI(ta.DataAssetsStored)
		if !ta.IsPersistentStorageIDS() {
			if len(daRecd) > 0 && (len(daSent) == 0) {
				risks = append(risks, r.createRisk(ta, strings.Join(daRecd, ", ")))
			}
		} else {
			//received, not sored nor sent
			if len(daRecd) > 0 && (len(daSent) == 0) && (len(daStored) == 0) {
				risks = append(risks, r.createRisk(ta, strings.Join(daRecd, ", ")))
			}

		}
	}
	return risks, nil
}

func (r *DataMinimizationAndDestructionRule) createRisk(technicalAsset *types.TechnicalAsset, titleMod string) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.VeryLikely, types.HighImpact),
		ExploitationLikelihood:       types.VeryLikely,
		ExploitationImpact:           types.HighImpact,
		Title:                        "<b>Data Minimization and Destruction</b> risk at <b> " + technicalAsset.Title + "</b> with PI(s): " + titleMod,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = r.Category().ID + "@" + technicalAsset.Id
	return risk
}
