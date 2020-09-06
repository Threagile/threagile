package missing_hardening

import (
	"github.com/threagile/threagile/model"
	"strconv"
)

const raaLimit = 55
const raaLimitReduced = 40

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-hardening",
		Title: "Missing Hardening",
		Description: "Technical assets with a Relative Attacker Attractiveness (RAA) value of " + strconv.Itoa(raaLimit) + " % or higher should be " +
			"explicitly hardened taking best practices and vendor hardening guides into account.",
		Impact:     "If this risk remains unmitigated, attackers might be able to easier attack high-value targets.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "System Hardening",
		Mitigation: "Try to apply all hardening best practices (like CIS benchmarks, OWASP recommendations, vendor " +
			"recommendations, DevSec Hardening Framework, DBSAT for Oracle databases, and others).",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: model.Operations,
		STRIDE:   model.Tampering,
		DetectionLogic: "In-scope technical assets with RAA values of " + strconv.Itoa(raaLimit) + " % or higher. " +
			"Generally for high-value targets like datastores, application servers, identity providers and ERP systems this limit is reduced to " + strconv.Itoa(raaLimitReduced) + " %",
		RiskAssessment:             "The risk rating depends on the sensitivity of the data processed or stored in the technical asset.",
		FalsePositives:             "Usually no false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        16,
	}
}

func SupportedTags() []string {
	return []string{"tomcat"}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope {
			if technicalAsset.RAA >= raaLimit || (technicalAsset.RAA >= raaLimitReduced &&
				(technicalAsset.Type == model.Datastore || technicalAsset.Technology == model.ApplicationServer || technicalAsset.Technology == model.IdentityProvider || technicalAsset.Technology == model.ERP)) {
				risks = append(risks, createRisk(technicalAsset))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Missing Hardening</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood:       model.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
