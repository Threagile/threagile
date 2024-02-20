package builtin

import (
	"fmt"
	"github.com/threagile/threagile/pkg/security/types"
	"strings"
)

type CodeBackdooringRule struct{}

func NewCodeBackdooringRule() *CodeBackdooringRule {
	return &CodeBackdooringRule{}
}

func (*CodeBackdooringRule) Category() types.RiskCategory {
	return types.RiskCategory{
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

func (r *CodeBackdooringRule) GenerateRisks(parsedModel *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology.IsDevelopmentRelevant() {
			if technicalAsset.Internet {
				risks = append(risks, r.createRisk(parsedModel, technicalAsset, true))
				continue
			}

			// TODO: ensure that even internet or unmanaged clients coming over a reverse-proxy or load-balancer like component are treated as if it was directly accessed/exposed on the internet or towards unmanaged dev clients

			//riskByLinkAdded := false
			for _, callerLink := range parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				caller := parsedModel.TechnicalAssets[callerLink.SourceId]
				if (!callerLink.VPN && caller.Internet) || caller.OutOfScope {
					risks = append(risks, r.createRisk(parsedModel, technicalAsset, true))
					//riskByLinkAdded = true
					break
				}
			}
		}
	}
	return risks
}

func (r *CodeBackdooringRule) createRisk(input *types.ParsedModel, technicalAsset types.TechnicalAsset, elevatedRisk bool) types.Risk {
	title := "<b>Code Backdooring</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.LowImpact
	if technicalAsset.Technology != types.CodeInspectionPlatform {
		if elevatedRisk {
			impact = types.MediumImpact
		}
		if technicalAsset.HighestConfidentiality(input) >= types.Confidential || technicalAsset.HighestIntegrity(input) >= types.Critical {
			impact = types.MediumImpact
			if elevatedRisk {
				impact = types.HighImpact
			}
		}
	}
	// data breach at all deployment targets
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, codeDeploymentTargetCommLink := range technicalAsset.CommunicationLinks {
		if codeDeploymentTargetCommLink.Usage == types.DevOps {
			for _, dataAssetID := range codeDeploymentTargetCommLink.DataAssetsSent {
				// it appears to be code when elevated integrity rating of sent data asset
				if input.DataAssets[dataAssetID].Integrity >= types.Important {
					// here we've got a deployment target which has its data assets at risk via deployment of backdoored code
					uniqueDataBreachTechnicalAssetIDs[codeDeploymentTargetCommLink.TargetId] = true
					break
				}
			}
		}
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	// create risk
	risk := types.Risk{
		CategoryId:                   r.Category().Id,
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

func (r *CodeBackdooringRule) MatchRisk(parsedModel *types.ParsedModel, risk string) bool {
	// todo
	return false
}

func (r *CodeBackdooringRule) ExplainRisk(parsedModel *types.ParsedModel, risk string) []string {
	categoryId := r.Category().Id
	explanation := make([]string, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		techAsset := parsedModel.TechnicalAssets[id]
		if strings.EqualFold(risk, categoryId+"@"+techAsset.Id) || strings.EqualFold(risk, categoryId+"@*") {
			if !techAsset.OutOfScope && (techAsset.Technology == types.SourcecodeRepository || techAsset.Technology == types.ArtifactRegistry) {
				riskExplanation := r.explainRisk(parsedModel, techAsset)
				if riskExplanation != nil {
					if len(explanation) > 0 {
						explanation = append(explanation, "")
					}

					explanation = append(explanation, []string{
						fmt.Sprintf("technical asset %q", techAsset.Id),
						fmt.Sprintf("  - out of scope: %v (=false)", techAsset.OutOfScope),
						fmt.Sprintf("  - technology: %v (is in [%q, %q])", techAsset.Technology, types.SourcecodeRepository, types.ArtifactRegistry),
					}...)

					if techAsset.IsTaggedWithAny("git") {
						explanation = append(explanation, "  is tagged with 'git'")
					}

					explanation = append(explanation, riskExplanation...)
				}
			}
		}
	}

	return explanation
}

func (r *CodeBackdooringRule) explainRisk(parsedModel *types.ParsedModel, technicalAsset types.TechnicalAsset) []string {
	explanation := make([]string, 0)
	impact := types.LowImpact
	if technicalAsset.HighestConfidentiality(parsedModel) == types.StrictlyConfidential ||
		technicalAsset.HighestIntegrity(parsedModel) == types.MissionCritical ||
		technicalAsset.HighestAvailability(parsedModel) == types.MissionCritical {
		impact = types.HighImpact

		explanation = append(explanation,
			fmt.Sprintf("    - impact is %v because", impact),
		)

		if technicalAsset.HighestConfidentiality(parsedModel) == types.StrictlyConfidential {
			explanation = append(explanation,
				fmt.Sprintf("      => highest confidentiality: %v (==%v)", technicalAsset.HighestConfidentiality(parsedModel), types.StrictlyConfidential),
			)
		}

		if technicalAsset.HighestIntegrity(parsedModel) == types.MissionCritical {
			explanation = append(explanation,
				fmt.Sprintf("      => highest integrity: %v (==%v)", technicalAsset.HighestIntegrity(parsedModel), types.MissionCritical),
			)
		}

		if technicalAsset.HighestAvailability(parsedModel) == types.MissionCritical {
			explanation = append(explanation,
				fmt.Sprintf("      => highest availability: %v (==%v)", technicalAsset.HighestAvailability(parsedModel), types.MissionCritical),
			)
		}
	} else if technicalAsset.HighestConfidentiality(parsedModel) >= types.Confidential ||
		technicalAsset.HighestIntegrity(parsedModel) >= types.Critical ||
		technicalAsset.HighestAvailability(parsedModel) >= types.Critical {
		impact = types.MediumImpact
		explanation = append(explanation,
			fmt.Sprintf("    - impact is %v because", impact),
		)

		if technicalAsset.HighestConfidentiality(parsedModel) == types.StrictlyConfidential {
			explanation = append(explanation,
				fmt.Sprintf("     =>  highest confidentiality: %v (>=%v)", technicalAsset.HighestConfidentiality(parsedModel), types.Confidential),
			)
		}

		if technicalAsset.HighestIntegrity(parsedModel) == types.MissionCritical {
			explanation = append(explanation,
				fmt.Sprintf("     =>  highest integrity: %v (==%v)", technicalAsset.HighestIntegrity(parsedModel), types.Critical),
			)
		}

		if technicalAsset.HighestAvailability(parsedModel) == types.MissionCritical {
			explanation = append(explanation,
				fmt.Sprintf("     =>  highest availability: %v (==%v)", technicalAsset.HighestAvailability(parsedModel), types.Critical),
			)
		}
	} else {
		explanation = append(explanation,
			fmt.Sprintf("     - impact is %v (default)", impact),
		)
	}

	return explanation
}
