package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type ContainerBaseImageBackdooringRule struct{}

func NewContainerBaseImageBackdooringRule() *ContainerBaseImageBackdooringRule {
	return &ContainerBaseImageBackdooringRule{}
}

func (*ContainerBaseImageBackdooringRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "container-baseimage-backdooring",
		Title: "Container Base Image Backdooring",
		Description: "When a technical asset is built using container technologies, Base Image Backdooring risks might arise where " +
			"base images and other layers used contain vulnerable components or backdoors." +
			"<br><br>See for example: <a href=\"https://techcrunch.com/2018/06/15/tainted-crypto-mining-containers-pulled-from-docker-hub/\">https://techcrunch.com/2018/06/15/tainted-crypto-mining-containers-pulled-from-docker-hub/</a>",
		Impact:     "If this risk is unmitigated, attackers might be able to deeply persist in the target system by executing code in deployed containers.",
		ASVS:       "V10 - Malicious Code Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
		Action:     "Container Infrastructure Hardening",
		Mitigation: "Apply hardening of all container infrastructures (see for example the <i>CIS-Benchmarks for Docker and Kubernetes</i> and the <i>Docker Bench for Security</i>). " +
			"Use only trusted base images of the original vendors, verify digital signatures and apply image creation best practices. " +
			"Also consider using Google's <i>Distroless</i> base images or otherwise very small base images. " +
			"Regularly execute container image scans with tools checking the layers for vulnerable components.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS/CSVS applied?",
		Function:       types.Operations,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope technical assets running as containers.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets.",
		FalsePositives: "Fully trusted (i.e. reviewed and cryptographically signed or similar) base images of containers can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        912,
	}
}

func (*ContainerBaseImageBackdooringRule) SupportedTags() []string {
	return []string{}
}

func (r *ContainerBaseImageBackdooringRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Machine == types.Container {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}

func (r *ContainerBaseImageBackdooringRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Container Base Image Backdooring</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.MediumImpact
	if technicalAsset.HighestProcessedConfidentiality(parsedModel) == types.StrictlyConfidential ||
		technicalAsset.HighestProcessedIntegrity(parsedModel) == types.MissionCritical ||
		technicalAsset.HighestProcessedAvailability(parsedModel) == types.MissionCritical {
		impact = types.HighImpact
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
