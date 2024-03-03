package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type MissingIdentityPropagationRule struct{}

func NewMissingIdentityPropagationRule() *MissingIdentityPropagationRule {
	return &MissingIdentityPropagationRule{}
}

func (*MissingIdentityPropagationRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "missing-identity-propagation",
		Title: "Missing Identity Propagation",
		Description: "Technical assets (especially multi-tenant systems), which usually process data for end users should " +
			"authorize every request based on the identity of the end user when the data flow is authenticated (i.e. non-public). " +
			"For DevOps usages at least a technical-user authorization is required.",
		Impact: "If this risk is unmitigated, attackers might be able to access or modify foreign data after a successful compromise of a component within " +
			"the system due to missing resource-based authorization checks.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
		Action:     "Identity Propagation and Resource-based Authorization",
		Mitigation: "When processing requests for end users if possible authorize in the backend against the propagated " +
			"identity of the end user. This can be achieved in passing JWTs or similar tokens and checking them in the backend " +
			"services. For DevOps usages apply at least a technical-user authorization.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope service-like technical assets which usually process data based on end user requests, if authenticated " +
			"(i.e. non-public), should authorize incoming requests based on the propagated end user identity when their rating is sensitive. " +
			"This is especially the case for all multi-tenant assets (there even less-sensitive rated ones). " +
			"DevOps usages are exempted from this risk.",
		RiskAssessment: "The risk rating (medium or high) " +
			"depends on the confidentiality, integrity, and availability rating of the technical asset.",
		FalsePositives: "Technical assets which do not process requests regarding functionality or data linked to end-users (customers) " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        284,
	}
}

func (*MissingIdentityPropagationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingIdentityPropagationRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.Technology.IsUsuallyProcessingEndUserRequests() &&
			(technicalAsset.Confidentiality >= types.Confidential ||
				technicalAsset.Integrity >= types.Critical ||
				technicalAsset.Availability >= types.Critical ||
				(technicalAsset.MultiTenant &&
					(technicalAsset.Confidentiality >= types.Restricted ||
						technicalAsset.Integrity >= types.Important ||
						technicalAsset.Availability >= types.Important))) {
			// check each incoming authenticated data flow
			commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, commLink := range commLinks {
				caller := input.TechnicalAssets[commLink.SourceId]
				if !caller.Technology.IsUsuallyAbleToPropagateIdentityToOutgoingTargets() || caller.Type == types.Datastore {
					continue
				}
				if commLink.Authentication != types.NoneAuthentication &&
					commLink.Authorization != types.EndUserIdentityPropagation {
					if commLink.Usage == types.DevOps && commLink.Authorization != types.NoneAuthorization {
						continue
					}
					highRisk := technicalAsset.Confidentiality == types.StrictlyConfidential ||
						technicalAsset.Integrity == types.MissionCritical ||
						technicalAsset.Availability == types.MissionCritical
					risks = append(risks, r.createRisk(input, technicalAsset, commLink, highRisk))
				}
			}
		}
	}
	return risks
}

func (r *MissingIdentityPropagationRule) createRisk(input *types.ParsedModel, technicalAsset types.TechnicalAsset, incomingAccess types.CommunicationLink, moreRisky bool) types.Risk {
	impact := types.LowImpact
	if moreRisky {
		impact = types.MediumImpact
	}
	risk := types.Risk{
		CategoryId:             r.Category().Id,
		Severity:               types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood: types.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Missing End User Identity Propagation</b> over communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + input.TechnicalAssets[incomingAccess.SourceId].Title + "</b> " +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + incomingAccess.Id + "@" + input.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
