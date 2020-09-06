package container_platform_escape

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "container-platform-escape",
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
		Function:       model.Operations,
		STRIDE:         model.ElevationOfPrivilege,
		DetectionLogic: "In-scope container platforms.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed and stored.",
		FalsePositives: "Container platforms not running parts of the target architecture can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{"docker", "kubernetes", "openshift"}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology == model.ContainerPlatform {
			risks = append(risks, createRisk(technicalAsset))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Container Platform Escape</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.HighImpact
	}
	// data breach at all container assets
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for id, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		if techAsset.Machine == model.Container {
			dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, id)
		}
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
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
