package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type ContainerPlatformEscapeRule struct{}

func NewContainerPlatformEscapeRule() *ContainerPlatformEscapeRule {
	return &ContainerPlatformEscapeRule{}
}

func (*ContainerPlatformEscapeRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "container-platform-escape",
		Title: "Container Platform Escape",
		Description: "Container platforms are especially interesting targets for attackers as they host big parts of a containerized runtime infrastructure. " +
			"When not configured and operated with security best practices in mind, attackers might exploit a vulnerability inside an container and escape towards " +
			"the platform as highly privileged users. These scenarios might give attackers capabilities to attack every other container as owning the container platform " +
			"(via container escape attacks) equals to owning every container.",
		Impact: "If this risk is unmitigated, attackers which have successfully compromised a container (via other vulnerabilities) " +
			"might be able to deeply persist in the target system by executing code in many deployed containers " +
			"and the container platform itself.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
		Action:     "Container Infrastructure Hardening",
		Mitigation: "Apply hardening of all container infrastructures. " +
			"<p>See for example the <i>CIS-Benchmarks for Docker and Kubernetes</i> " +
			"as well as the <i>Docker Bench for Security</i> ( <a href=\"https://github.com/docker/docker-bench-security\">https://github.com/docker/docker-bench-security</a> ) " +
			"or <i>InSpec Checks for Docker and Kubernetes</i> ( <a href=\"https://github.com/dev-sec/cis-kubernetes-benchmark\">https://github.com/dev-sec/cis-docker-benchmark</a> and <a href=\"https://github.com/dev-sec/cis-kubernetes-benchmark\">https://github.com/dev-sec/cis-kubernetes-benchmark</a> ). " +
			"Use only trusted base images, verify digital signatures and apply image creation best practices. Also consider using Google's <b>Distroless</i> base images or otherwise very small base images. " +
			"Apply namespace isolation and nod affinity to separate pods from each other in terms of access and nodes the same style as you separate data.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS or CSVS chapter applied?",
		Function:       types.Operations,
		STRIDE:         types.ElevationOfPrivilege,
		DetectionLogic: "In-scope container platforms.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Container platforms not running parts of the target architecture can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func (*ContainerPlatformEscapeRule) SupportedTags() []string {
	return []string{"docker", "kubernetes", "openshift"}
}

func (r *ContainerPlatformEscapeRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technologies.GetAttribute(types.ContainerPlatform) {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}

func (r *ContainerPlatformEscapeRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Container Platform Escape</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.MediumImpact
	if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical ||
		parsedModel.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	// data breach at all container assets
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for id, techAsset := range parsedModel.TechnicalAssets {
		if techAsset.Machine == types.Container {
			dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, id)
		}
	}
	// create risk
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
