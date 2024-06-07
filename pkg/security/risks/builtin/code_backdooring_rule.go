package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type CodeBackdooringRule struct{}

func NewCodeBackdooringRule() *CodeBackdooringRule {
	return &CodeBackdooringRule{}
}

func (*CodeBackdooringRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "code-backdooring",
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
		Function: types.Operations,
		STRIDE:   types.Tampering,
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

func (*CodeBackdooringRule) SupportedTags() []string {
	return []string{}
}

func (r *CodeBackdooringRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technologies.GetAttribute(types.IsDevelopmentRelevant) {
			if technicalAsset.Internet {
				risks = append(risks, r.createRisk(parsedModel, technicalAsset))
				continue
			}

			// TODO: ensure that even internet or unmanaged clients coming over a reverse-proxy or load-balancer like component are treated as if it was directly accessed/exposed on the internet or towards unmanaged dev clients

			for _, callerLink := range parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				caller := parsedModel.TechnicalAssets[callerLink.SourceId]
				if !callerLink.VPN && caller.Internet {
					risks = append(risks, r.createRisk(parsedModel, technicalAsset))
					break
				}
			}
		}
	}
	return risks, nil
}

func (r *CodeBackdooringRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Code Backdooring</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.LowImpact
	if !technicalAsset.Technologies.GetAttribute(types.CodeInspectionPlatform) {
		impact = types.MediumImpact
		if technicalAsset.HighestProcessedConfidentiality(input) >= types.Confidential || technicalAsset.HighestProcessedIntegrity(input) >= types.Critical {
			impact = types.HighImpact
		}
	}
	// data breach at all deployment targets
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, codeDeploymentTargetCommLink := range technicalAsset.CommunicationLinks {
		if codeDeploymentTargetCommLink.Usage != types.DevOps {
			continue
		}
		for _, dataAssetID := range codeDeploymentTargetCommLink.DataAssetsSent {
			// it appears to be code when elevated integrity rating of sent data asset
			if input.DataAssets[dataAssetID].Integrity >= types.Important {
				// here we've got a deployment target which has its data assets at risk via deployment of backdoored code
				uniqueDataBreachTechnicalAssetIDs[codeDeploymentTargetCommLink.TargetId] = true
				break
			}
		}
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
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
