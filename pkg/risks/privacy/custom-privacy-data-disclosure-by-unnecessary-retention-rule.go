package privacy

import (
	"github.com/threagile/threagile/pkg/types"
)

type DataDisclosureByUnnecessaryRetentionRule struct{}

func NewDataDisclosureByUnnecessaryRetentionRule() *DataDisclosureByUnnecessaryRetentionRule {
	return &DataDisclosureByUnnecessaryRetentionRule{}
}

func (*DataDisclosureByUnnecessaryRetentionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "data-disclosure-by-unnecessary-retention",
		Title:                      "Data Disclosure by Unnecessary Retention",
		Description:                "When personal data processing and storage of personal information continues by an asset beyond the operational need then Data Disclosure by Unnecessary Retention privacy risk can arise.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check NIST Privacy Controls Framework",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Implement data retention policies.",
		Mitigation:                 "Assess the data retention policies for the model by considering the duration for which personal information is stored and whether a process exists for removing data after retention period is met.",
		Check:                      "Are Data Disclosure concerns as described from LINDDUN threat trees (DD.3.4) addressed?",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "If DeletePostFunctionalNeed == FALSE, then generate a threat.",
		RiskAssessment:             "Depends on the type of data assets involved i.e. Personal Information (PI) or not",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*DataDisclosureByUnnecessaryRetentionRule) SupportedTags() []string {
	return []string{"data-disclosure-by-unnecessary-retention"}
}

func (r *DataDisclosureByUnnecessaryRetentionRule) GenerateRisks(parsedModelRoot *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	setDA := make([]string, 0)

	if parsedModelRoot.DeletePostFunctionalNeed {
		return risks, nil
	}

	for _, da := range parsedModelRoot.DataAssets {
		setDA = append(setDA, da.Id)
	}

	setPI := parsedModelRoot.GetPI(setDA)

	for _, pi := range setPI {
		risks = append(risks, r.createRisk(parsedModelRoot.DataAssets[pi]))
	}

	return risks, nil

}

func (r *DataDisclosureByUnnecessaryRetentionRule) createRisk(dataAsset *types.DataAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:              r.Category().ID,
		Severity:                types.RiskSeverity(types.MediumImpact),
		ExploitationLikelihood:  types.Unlikely,
		ExploitationImpact:      types.MediumImpact,
		Title:                   "<b>Data disclosure by unnecessary retention</b> risk for <b> data asset: " + dataAsset.Id + "</b>.",
		MostRelevantDataAssetId: dataAsset.Id,
		DataBreachProbability:   types.Possible,
	}
	risk.SyntheticId = risk.CategoryId + "@" + dataAsset.Id
	return risk
}
