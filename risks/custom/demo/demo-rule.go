package main

import (
	"github.com/threagile/threagile/model"
)

type customRiskRule string

// exported as symbol (here simply as variable to interface to bundle many functions under one symbol) named "CustomRiskRule"
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "demo",
		Title:                      "Just a Demo",
		Description:                "Demo Description",
		Impact:                     "Demo Impact",
		ASVS:                       "Demo ASVS",
		CheatSheet:                 "https://example.com",
		Action:                     "Demo Action",
		Mitigation:                 "Demo Mitigation",
		Check:                      "Demo Check",
		Function:                   model.Development,
		STRIDE:                     model.Tampering,
		DetectionLogic:             "Demo Detection",
		RiskAssessment:             "Demo Risk Assessment",
		FalsePositives:             "Demo False Positive.",
		ModelFailurePossibleReason: false,
		CWE:                        0,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{"demo tag"}
}

func (r customRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		risks = append(risks, createRisk(techAsset))
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.VeryLikely, model.MediumImpact),
		ExploitationLikelihood:       model.VeryLikely,
		ExploitationImpact:           model.MediumImpact,
		Title:                        "<b>Demo</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
