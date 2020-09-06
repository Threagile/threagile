package missing_identity_propagation

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-identity-propagation",
		Title: "Missing Identity Propagation",
		Description: "Technical assets (especially multi-tenant systems), which usually process data for endusers should " +
			"authorize every request based on the identity of the enduser when the data flow is authenticated (i.e. non-public). " +
			"For DevOps usages at least a technical-user authorization is required.",
		Impact: "If this risk is unmitigated, attackers might be able to access or modify foreign data after a successful compromise of a component within " +
			"the system due to missing resource-based authorization checks.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
		Action:     "Identity Propagation and Resource-based Authorization",
		Mitigation: "When processing requests for endusers if possible authorize in the backend against the propagated " +
			"identity of the enduser. This can be achieved in passing JWTs or similar tokens and checking them in the backend " +
			"services. For DevOps usages apply at least a technical-user authorization.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: model.Architecture,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "In-scope service-like technical assets which usually process data based on enduser requests, if authenticated " +
			"(i.e. non-public), should authorize incoming requests based on the propagated enduser identity when their rating is sensitive. " +
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

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.Technology.IsUsuallyProcessingEnduserRequests() &&
			(technicalAsset.Confidentiality >= model.Confidential ||
				technicalAsset.Integrity >= model.Critical ||
				technicalAsset.Availability >= model.Critical ||
				(technicalAsset.MultiTenant &&
					(technicalAsset.Confidentiality >= model.Restricted ||
						technicalAsset.Integrity >= model.Important ||
						technicalAsset.Availability >= model.Important))) {
			// check each incoming authenticated data flow
			commLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, commLink := range commLinks {
				caller := model.ParsedModelRoot.TechnicalAssets[commLink.SourceId]
				if !caller.Technology.IsUsuallyAbleToPropagateIdentityToOutgoingTargets() || caller.Type == model.Datastore {
					continue
				}
				if commLink.Authentication != model.NoneAuthentication &&
					commLink.Authorization != model.EnduserIdentityPropagation {
					if commLink.Usage == model.DevOps && commLink.Authorization != model.NoneAuthorization {
						continue
					}
					highRisk := technicalAsset.Confidentiality == model.StrictlyConfidential ||
						technicalAsset.Integrity == model.MissionCritical ||
						technicalAsset.Availability == model.MissionCritical
					risks = append(risks, createRisk(technicalAsset, commLink, highRisk))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingAccess model.CommunicationLink, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood: model.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Missing Enduser Identity Propagation</b> over communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Title + "</b> " +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + incomingAccess.Id + "@" + model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
