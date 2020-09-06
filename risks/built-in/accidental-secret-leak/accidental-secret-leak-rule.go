package accidental_secret_leak

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "accidental-secret-leak",
		Title: "Accidental Secret Leak",
		Description: "Sourcecode repositories (including their histories) as well as artifact registries can accidentally contain secrets like " +
			"checked-in or packaged-in passwords, API tokens, certificates, crypto keys, etc.",
		Impact: "If this risk is unmitigated, attackers which have access to affected sourcecode repositories or artifact registries might " +
			"find secrets accidentally checked-in.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Establish measures preventing accidental check-in or package-in of secrets into sourcecode repositories " +
			"and artifact registries. This starts by using good .gitignore and .dockerignore files, but does not stop there. " +
			"See for example tools like <i>\"git-secrets\" or \"Talisman\"</i> to have check-in preventive measures for secrets. " +
			"Consider also to regularly scan your repositories for secrets accidentally checked-in using scanning tools like <i>\"gitleaks\" or \"gitrob\"</i>.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   model.Operations,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "In-scope sourcecode repositories and artifact registries.",
		RiskAssessment:             "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed and stored.",
		FalsePositives:             "Usually no false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func SupportedTags() []string {
	return []string{"git", "nexus"}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !techAsset.OutOfScope &&
			(techAsset.Technology == model.SourcecodeRepository || techAsset.Technology == model.ArtifactRegistry) {
			var risk model.Risk
			if techAsset.IsTaggedWithAny("git") {
				risk = createRisk(techAsset, "Git", "Git Leak Prevention")
			} else {
				risk = createRisk(techAsset, "", "")
			}
			risks = append(risks, risk)
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, prefix, details string) model.Risk {
	if len(prefix) > 0 {
		prefix = " (" + prefix + ")"
	}
	title := "<b>Accidental Secret Leak" + prefix + "</b> risk at <b>" + technicalAsset.Title + "</b>"
	if len(details) > 0 {
		title += ": <u>" + details + "</u>"
	}
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() >= model.Confidential ||
		technicalAsset.HighestIntegrity() >= model.Critical ||
		technicalAsset.HighestAvailability() >= model.Critical {
		impact = model.MediumImpact
	}
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.HighImpact
	}
	// create risk
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
