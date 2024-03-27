package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type WrongCommunicationLinkContentRule struct{}

func NewWrongCommunicationLinkContentRule() *WrongCommunicationLinkContentRule {
	return &WrongCommunicationLinkContentRule{}
}

func (*WrongCommunicationLinkContentRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "wrong-communication-link-content",
		Title: "Wrong Communication Link Content",
		Description: "When a communication link is defined as readonly, but does not receive any data asset, " +
			"or when it is defined as not readonly, but does not send any data asset, it is likely to be a model failure.",
		Impact:     "If this potential model error is not fixed, some risks might not be visible.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
		Action:     "Model Consistency",
		Mitigation: "Try to model the correct readonly flag and/or data sent/received of communication links. " +
			"Also try to use  communication link types matching the target technology/machine types.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   types.Architecture,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Communication links with inconsistent data assets being sent/received not matching their readonly flag or otherwise inconsistent protocols not matching the target technology type.",
		RiskAssessment:             types.LowSeverity.String(),
		FalsePositives:             "Usually no false positives as this looks like an incomplete model.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func (*WrongCommunicationLinkContentRule) SupportedTags() []string {
	return []string{}
}

func (r *WrongCommunicationLinkContentRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, techAsset := range input.TechnicalAssets {
		for _, commLink := range techAsset.CommunicationLinks {
			// check readonly consistency
			if commLink.Readonly {
				if len(commLink.DataAssetsReceived) == 0 {
					risks = append(risks, r.createRisk(techAsset, commLink,
						"(data assets sent/received not matching the communication link's readonly flag)"))
				}
			} else {
				if len(commLink.DataAssetsSent) == 0 {
					risks = append(risks, r.createRisk(techAsset, commLink,
						"(data assets sent/received not matching the communication link's readonly flag)"))
				}
			}
			// check for protocol inconsistencies
			targetAsset := input.TechnicalAssets[commLink.TargetId]
			if commLink.Protocol == types.InProcessLibraryCall && !targetAsset.Technologies.GetAttribute(types.Library) {
				risks = append(risks, r.createRisk(techAsset, commLink,
					"(protocol type \""+types.InProcessLibraryCall.String()+"\" does not match target technology type \""+targetAsset.Technologies.String()+"\": expected \""+types.Library+"\")"))
			}
			if commLink.Protocol == types.LocalFileAccess && !targetAsset.Technologies.GetAttribute(types.LocalFileSystem) {
				risks = append(risks, r.createRisk(techAsset, commLink,
					"(protocol type \""+types.LocalFileAccess.String()+"\" does not match target technology type \""+targetAsset.Technologies.String()+"\": expected \""+types.LocalFileSystem+"\")"))
			}
			if commLink.Protocol == types.ContainerSpawning && targetAsset.Machine != types.Container {
				risks = append(risks, r.createRisk(techAsset, commLink,
					"(protocol type \""+types.ContainerSpawning.String()+"\" does not match target machine type \""+targetAsset.Machine.String()+"\": expected \""+types.Container.String()+"\")"))
			}
		}
	}
	return risks
}

func (r *WrongCommunicationLinkContentRule) createRisk(technicalAsset types.TechnicalAsset, commLink types.CommunicationLink, reason string) types.Risk {
	title := "<b>Wrong Communication Link Content</b> " + reason + " at <b>" + technicalAsset.Title + "</b> " +
		"regarding communication link <b>" + commLink.Title + "</b>"
	risk := types.Risk{
		CategoryId:                      r.Category().Id,
		Severity:                        types.CalculateSeverity(types.Unlikely, types.LowImpact),
		ExploitationLikelihood:          types.Unlikely,
		ExploitationImpact:              types.LowImpact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: commLink.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id + "@" + commLink.Id
	return risk
}
