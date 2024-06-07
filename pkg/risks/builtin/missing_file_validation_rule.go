package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingFileValidationRule struct{}

func NewMissingFileValidationRule() *MissingFileValidationRule {
	return &MissingFileValidationRule{}
}

func (*MissingFileValidationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "missing-file-validation",
		Title:       "Missing File Validation",
		Description: "When a technical asset accepts files, these input files should be strictly validated about filename and type.",
		Impact:      "If this risk is unmitigated, attackers might be able to provide malicious files to the application.",
		ASVS:        "V12 - File and Resources Verification Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
		Action:      "File Validation",
		Mitigation: "Filter by file extension and discard (if feasible) the name provided. Whitelist the accepted file types " +
			"and determine the mime-type on the server-side (for example via \"Apache Tika\" or similar checks). If the file is retrievable by " +
			"end users and/or backoffice employees, consider performing scans for popular malware (if the files can be retrieved much later than they " +
			"were uploaded, also apply a fresh malware scan during retrieval to scan with newer signatures of popular malware). Also enforce " +
			"limits on maximum file size to avoid denial-of-service like scenarios.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Spoofing,
		DetectionLogic: "In-scope technical assets with custom-developed code accepting file data formats.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Fully trusted (i.e. cryptographically signed or similar) files can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        434,
	}
}

func (*MissingFileValidationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingFileValidationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.CustomDevelopedParts {
			continue
		}
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == types.File {
				risks = append(risks, r.createRisk(input, technicalAsset))
			}
		}
	}
	return risks, nil
}

func (r *MissingFileValidationRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Missing File Validation</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.LowImpact
	if technicalAsset.HighestProcessedConfidentiality(input) == types.StrictlyConfidential ||
		technicalAsset.HighestProcessedIntegrity(input) == types.MissionCritical ||
		technicalAsset.HighestProcessedAvailability(input) == types.MissionCritical {
		impact = types.MediumImpact
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.VeryLikely, impact),
		ExploitationLikelihood:       types.VeryLikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
