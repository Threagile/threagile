package privacy

import (
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

type DataMinimizationAndExclusionRule struct{}

func NewDataMinimizationAndExclusionRule() *DataMinimizationAndExclusionRule {
	return &DataMinimizationAndExclusionRule{}
}

func (*DataMinimizationAndExclusionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "data-minimization-and-exclusion",
		Title:                      "Data Minimization and Exclusion",
		Description:                "When a personal information (PI) is received by a technical asset when it does not need it Data Minimization and Exclusion risk arises. Need of an asset is when it is either supposed to process or store it.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check NIST Privacy Controls Framework",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Implement data minimization principles.",
		Mitigation:                 "Implement data minimization principles. Check which regulations apply to your processing activities and the system you use.",
		Check:                      "Are Non-compliance concerns as described from LINDDUN threat trees (Nc.1.1.2) addressed?",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Rule identifies risks where personal data (PI) is received by a technical asset but not used (i.e., not processed, stored, or sent).",
		RiskAssessment:             "The risk rating depends on sufficient access control mechanisms of inbound access request.",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*DataMinimizationAndExclusionRule) SupportedTags() []string {
	return []string{"data-minimization-and-exclusion"}
}

func (r *DataMinimizationAndExclusionRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)

	if parsedModel.Deidentified {
		return risks, nil
	}

	daRecvdMap := parsedModel.GetDARecvd()
	for _, ta := range parsedModel.TechnicalAssets {
		daRecvdInMap := daRecvdMap[ta.Id]
		daProcessedOrStoredMap := make(map[string]bool)
		for _, daProcessed := range ta.DataAssetsProcessed {
			_, p := daProcessedOrStoredMap[daProcessed]
			if !p {
				daProcessedOrStoredMap[daProcessed] = true
			}
		}
		for _, daStored := range ta.DataAssetsStored {
			_, p := daProcessedOrStoredMap[daStored]
			if !p {
				daProcessedOrStoredMap[daStored] = true
			}
		}

		nonReqDataAsset := make([]string, 0)
		for k := range daRecvdInMap {
			_, p := daProcessedOrStoredMap[k]
			if !p {
				nonReqDataAsset = append(nonReqDataAsset, k)
			}
		}

		nonReqPI := parsedModel.GetPI(nonReqDataAsset)
		if len(nonReqPI) > 0 {
			risks = append(risks, r.createRisk(ta, strings.Join(nonReqPI, ", ")))
		}
	}
	return risks, nil
}

func (r *DataMinimizationAndExclusionRule) createRisk(technicalAsset *types.TechnicalAsset, titleMod string) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.VeryLikely, types.HighImpact),
		ExploitationLikelihood:       types.VeryLikely,
		ExploitationImpact:           types.HighImpact,
		Title:                        "<b>Data Minimization And Exclusion</b> risk at <b> " + technicalAsset.Title + "</b> with PI(s): " + titleMod,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
