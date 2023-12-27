package mixed_targets_on_shared_runtime

import (
	"sort"

	"github.com/threagile/threagile/pkg/security/types"
)

func Rule() types.RiskRule {
	return types.RiskRule{
		Category:      Category,
		SupportedTags: SupportedTags,
		GenerateRisks: GenerateRisks,
	}
}

func Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "mixed-targets-on-shared-runtime",
		Title: "Mixed Targets on Shared Runtime",
		Description: "Different attacker targets (like frontend and backend/datastore components) should not be running on the same " +
			"shared (underlying) runtime.",
		Impact: "If this risk is unmitigated, attackers successfully attacking other components of the system might have an easy path towards " +
			"more valuable targets, as they are running on the same shared runtime.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Runtime Separation",
		Mitigation: "Use separate runtime environments for running different target components or apply similar separation styles to " +
			"prevent load- or breach-related problems originating from one more attacker-facing asset impacts also the " +
			"other more critical rated backend/datastore assets.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Operations,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "Shared runtime running technical assets of different trust-boundaries is at risk. " +
			"Also mixing backend/datastore with frontend components on the same shared runtime is considered a risk.",
		RiskAssessment: "The risk rating (low or medium) depends on the confidentiality, integrity, and availability rating of " +
			"the technical asset running on the shared runtime.",
		FalsePositives: "When all assets running on the shared runtime are hardened and protected to the same extend as if all were " +
			"containing/processing highly sensitive data.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
	keys := make([]string, 0)
	for k := range input.SharedRuntimes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		sharedRuntime := input.SharedRuntimes[key]
		currentTrustBoundaryId := ""
		hasFrontend, hasBackend := false, false
		riskAdded := false
		for _, technicalAssetId := range sharedRuntime.TechnicalAssetsRunning {
			technicalAsset := input.TechnicalAssets[technicalAssetId]
			if len(currentTrustBoundaryId) > 0 && currentTrustBoundaryId != technicalAsset.GetTrustBoundaryId(input) {
				risks = append(risks, createRisk(input, sharedRuntime))
				riskAdded = true
				break
			}
			currentTrustBoundaryId = technicalAsset.GetTrustBoundaryId(input)
			if technicalAsset.Technology.IsExclusivelyFrontendRelated() {
				hasFrontend = true
			}
			if technicalAsset.Technology.IsExclusivelyBackendRelated() {
				hasBackend = true
			}
		}
		if !riskAdded && hasFrontend && hasBackend {
			risks = append(risks, createRisk(input, sharedRuntime))
		}
	}
	return risks
}

func createRisk(input *types.ParsedModel, sharedRuntime types.SharedRuntime) types.Risk {
	impact := types.LowImpact
	if isMoreRisky(input, sharedRuntime) {
		impact = types.MediumImpact
	}
	risk := types.Risk{
		CategoryId:             Category().Id,
		Severity:               types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood: types.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Mixed Targets on Shared Runtime</b> named <b>" + sharedRuntime.Title + "</b> might enable attackers moving from one less " +
			"valuable target to a more valuable one", // TODO list at least the assets in the text which are running on the shared HW
		MostRelevantSharedRuntimeId: sharedRuntime.Id,
		DataBreachProbability:       types.Improbable,
		DataBreachTechnicalAssetIDs: sharedRuntime.TechnicalAssetsRunning,
	}
	risk.SyntheticId = risk.CategoryId + "@" + sharedRuntime.Id
	return risk
}

func isMoreRisky(input *types.ParsedModel, sharedRuntime types.SharedRuntime) bool {
	for _, techAssetId := range sharedRuntime.TechnicalAssetsRunning {
		techAsset := input.TechnicalAssets[techAssetId]
		if techAsset.Confidentiality == types.StrictlyConfidential || techAsset.Integrity == types.MissionCritical ||
			techAsset.Availability == types.MissionCritical {
			return true
		}
	}
	return false
}
