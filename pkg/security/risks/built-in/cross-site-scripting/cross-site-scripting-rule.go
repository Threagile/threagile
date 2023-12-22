package cross_site_scripting

import (
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/types"
)

func Rule() model.CustomRiskRule {
	return model.CustomRiskRule{
		Category:      Category,
		SupportedTags: SupportedTags,
		GenerateRisks: GenerateRisks,
	}
}

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "cross-site-scripting",
		Title: "Cross-Site Scripting (XSS)",
		Description: "For each web application Cross-Site Scripting (XSS) risks might arise. In terms " +
			"of the overall risk level take other applications running on the same domain into account as well.",
		Impact:     "If this risk remains unmitigated, attackers might be able to access individual victim sessions and steal or modify user data.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		Action:     "XSS Prevention",
		Mitigation: "Try to encode all values sent back to the browser and also handle DOM-manipulations in a safe way " +
			"to avoid DOM-based XSS. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope web applications.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed or stored in the web application.",
		FalsePositives: "When the technical asset " +
			"is not accessed via a browser-like component (i.e not by a human user initiating the request that " +
			"gets passed through all components until it reaches the web application) this can be considered a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        79,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks(input *model.ParsedModel) []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technology.IsWebApplication() { // TODO: also mobile clients or rich-clients as long as they use web-view...
			continue
		}
		risks = append(risks, createRisk(input, technicalAsset))
	}
	return risks
}

func createRisk(parsedModel *model.ParsedModel, technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Cross-Site Scripting (XSS)</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.MediumImpact
	if technicalAsset.HighestConfidentiality(parsedModel) == types.StrictlyConfidential || technicalAsset.HighestIntegrity(parsedModel) == types.MissionCritical {
		impact = types.HighImpact
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(types.Likely, impact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
