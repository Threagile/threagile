package code_backdooring

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "code-backdooring",
		Title: "Code Backdooring",
		Description: "For each build-pipeline component Code Backdooring risks might arise where attackers compromise the build-pipeline " +
			"in order to let backdoored artifacts be shipped into production. Aside from direct code backdooring this includes " +
			"backdooring of dependencies and even of more lower-level build infrastructure, like backdooring compilers (similar to what the XcodeGhost malware did) or dependencies.",
		Impact: "If this risk remains unmitigated, attackers might be able to execute code on and completely takeover " +
			"production environments.",
		ASVS:       "V10 - Malicious Code Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Reduce the attack surface of backdooring the build pipeline by not directly exposing the build pipeline " +
			"components on the public internet and also not exposing it in front of unmanaged (out-of-scope) developer clients." +
			"Also consider the use of code signing to prevent code modifications.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: model.Operations,
		STRIDE:   model.Tampering,
		DetectionLogic: "In-scope development relevant technical assets which are either accessed by out-of-scope unmanaged " +
			"developer clients and/or are directly accessed by any kind of internet-located (non-VPN) component or are themselves directly located " +
			"on the internet.",
		RiskAssessment: "The risk rating depends on the confidentiality and integrity rating of the code being handled and deployed " +
			"as well as the placement/calling of this technical asset on/from the internet.", // TODO also take the CIA rating of the deployment targets (and their data) into account?
		FalsePositives: "When the build-pipeline and sourcecode-repo is not exposed to the internet and considered fully " +
			"trusted (which implies that all accessing clients are also considered fully trusted in terms of their patch management " +
			"and applied hardening, which must be equivalent to a managed developer client environment) this can be considered a false positive " +
			"after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        912,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology.IsDevelopmentRelevant() {
			if technicalAsset.Internet {
				risks = append(risks, createRisk(technicalAsset, true))
				continue
			}

			// TODO: ensure that even internet or unmanaged clients coming over a reverse-proxy or load-balancer like component are treated as if it was directly accessed/exposed on the internet or towards unmanaged dev clients

			//riskByLinkAdded := false
			for _, callerLink := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				caller := model.ParsedModelRoot.TechnicalAssets[callerLink.SourceId]
				if (!callerLink.VPN && caller.Internet) || caller.OutOfScope {
					risks = append(risks, createRisk(technicalAsset, true))
					//riskByLinkAdded = true
					break
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, elevatedRisk bool) model.Risk {
	title := "<b>Code Backdooring</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.LowImpact
	if technicalAsset.Technology != model.CodeInspectionPlatform {
		if elevatedRisk {
			impact = model.MediumImpact
		}
		if technicalAsset.HighestConfidentiality() >= model.Confidential || technicalAsset.HighestIntegrity() >= model.Critical {
			impact = model.MediumImpact
			if elevatedRisk {
				impact = model.HighImpact
			}
		}
	}
	// data breach at all deployment targets
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, codeDeploymentTargetCommLink := range technicalAsset.CommunicationLinks {
		if codeDeploymentTargetCommLink.Usage == model.DevOps {
			for _, dataAssetID := range codeDeploymentTargetCommLink.DataAssetsSent {
				// it appears to be code when elevated integrity rating of sent data asset
				if model.ParsedModelRoot.DataAssets[dataAssetID].Integrity >= model.Important {
					// here we've got a deployment target which has its data assets at risk via deployment of backdoored code
					uniqueDataBreachTechnicalAssetIDs[codeDeploymentTargetCommLink.TargetId] = true
					break
				}
			}
		}
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key, _ := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
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
