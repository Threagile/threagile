package missing_hardening

import (
	"strconv"

	"github.com/threagile/threagile/pkg/security/types"
)

const raaLimit = 55
const raaLimitReduced = 40

func Rule() types.RiskRule {
	return types.RiskRule{
		Category:      Category,
		SupportedTags: SupportedTags,
		GenerateRisks: GenerateRisks,
	}
}

func Category() types.RiskCategory {
	return types.RiskCategory{
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
		Function: types.Operations,
		STRIDE:   types.Tampering,
		DetectionLogic: "In-scope technical assets with RAA values of " + strconv.Itoa(raaLimit) + " % or higher. " +
			"Generally for high-value targets like data stores, application servers, identity providers and ERP systems this limit is reduced to " + strconv.Itoa(raaLimitReduced) + " %",
		RiskAssessment:             "The risk rating depends on the sensitivity of the data processed or stored in the technical asset.",
		FalsePositives:             "Usually no false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        16,
	}
}

func SupportedTags() []string {
	return []string{"tomcat"}
}

func GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.OutOfScope {
			if technicalAsset.RAA >= raaLimit || (technicalAsset.RAA >= raaLimitReduced &&
				(technicalAsset.Type == types.Datastore || technicalAsset.Technology == types.ApplicationServer || technicalAsset.Technology == types.IdentityProvider || technicalAsset.Technology == types.ERP)) {
				risks = append(risks, createRisk(input, technicalAsset))
			}
		}
	}
	return risks
}

func createRisk(input *types.ParsedModel, technicalAsset types.TechnicalAsset) types.Risk {
	title := "<b>Missing Hardening</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.LowImpact
	if technicalAsset.HighestConfidentiality(input) == types.StrictlyConfidential || technicalAsset.HighestIntegrity(input) == types.MissionCritical {
		impact = types.MediumImpact
	}
	risk := types.Risk{
		CategoryId:                   Category().Id,
		Severity:                     types.CalculateSeverity(types.Likely, impact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
