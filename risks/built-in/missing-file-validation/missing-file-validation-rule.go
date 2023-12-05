package missing_file_validation

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "missing-file-validation",
		Title:       "Missing File Validation",
		Description: "When a technical asset accepts files, these input files should be strictly validated about filename and type.",
		Impact:      "If this risk is unmitigated, attackers might be able to provide malicious files to the application.",
		ASVS:        "V12 - File and Resources Verification Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
		Action:      "File Validation",
		Mitigation: "Filter by file extension and discard (if feasible) the name provided. Whitelist the accepted file types " +
			"and determine the mime-type on the server-side (for example via \"Apache Tika\" or similar checks). If the file is retrievable by " +
			"endusers and/or backoffice employees, consider performing scans for popular malware (if the files can be retrieved much later than they " +
			"were uploaded, also apply a fresh malware scan during retrieval to scan with newer signatures of popular malware). Also enforce " +
			"limits on maximum file size to avoid denial-of-service like scenarios.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Development,
		STRIDE:         model.Spoofing,
		DetectionLogic: "In-scope technical assets with custom-developed code accepting file data formats.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed and stored.",
		FalsePositives: "Fully trusted (i.e. cryptographically signed or similar) files can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        434,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.CustomDevelopedParts {
			continue
		}
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == model.File {
				risks = append(risks, createRisk(technicalAsset))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Missing File Validation</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.VeryLikely, impact),
		ExploitationLikelihood:       model.VeryLikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
