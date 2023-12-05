package missing_authentication_second_factor

import (
	"github.com/threagile/threagile/model"
	"github.com/threagile/threagile/risks/built-in/missing-authentication"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-authentication-second-factor",
		Title: "Missing Two-Factor Authentication (2FA)",
		Description: "Technical assets (especially multi-tenant systems) should authenticate incoming requests with " +
			"two-factor (2FA) authentication when the asset processes or stores highly sensitive data (in terms of confidentiality, integrity, and availability) and is accessed by humans.",
		Impact:     "If this risk is unmitigated, attackers might be able to access or modify highly sensitive data without strong authentication.",
		ASVS:       "V2 - Authentication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
		Action:     "Authentication with Second Factor (2FA)",
		Mitigation: "Apply an authentication method to the technical asset protecting highly sensitive data via " +
			"two-factor authentication for human users.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: model.BusinessSide,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets (except " + model.LoadBalancer.String() + ", " + model.ReverseProxy.String() + ", " + model.WAF.String() + ", " + model.IDS.String() + ", and " + model.IPS.String() + ") should authenticate incoming requests via two-factor authentication (2FA) " +
			"when the asset processes or stores highly sensitive data (in terms of confidentiality, integrity, and availability) and is accessed by a client used by a human user.",
		RiskAssessment: model.MediumSeverity.String(),
		FalsePositives: "Technical assets which do not process requests regarding functionality or data linked to end-users (customers) " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        308,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope ||
			technicalAsset.Technology.IsTrafficForwarding() ||
			technicalAsset.Technology.IsUnprotectedCommsTolerated() {
			continue
		}
		if technicalAsset.HighestConfidentiality() >= model.Confidential ||
			technicalAsset.HighestIntegrity() >= model.Critical ||
			technicalAsset.HighestAvailability() >= model.Critical ||
			technicalAsset.MultiTenant {
			// check each incoming data flow
			commLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, commLink := range commLinks {
				caller := model.ParsedModelRoot.TechnicalAssets[commLink.SourceId]
				if caller.Technology.IsUnprotectedCommsTolerated() || caller.Type == model.Datastore {
					continue
				}
				if caller.UsedAsClientByHuman {
					moreRisky := commLink.HighestConfidentiality() >= model.Confidential ||
						commLink.HighestIntegrity() >= model.Critical
					if moreRisky && commLink.Authentication != model.TwoFactor {
						risks = append(risks, missing_authentication.CreateRisk(technicalAsset, commLink, commLink, "", model.MediumImpact, model.Unlikely, true, Category()))
					}
				} else if caller.Technology.IsTrafficForwarding() {
					// Now try to walk a call chain up (1 hop only) to find a caller's caller used by human
					callersCommLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[caller.Id]
					for _, callersCommLink := range callersCommLinks {
						callersCaller := model.ParsedModelRoot.TechnicalAssets[callersCommLink.SourceId]
						if callersCaller.Technology.IsUnprotectedCommsTolerated() || callersCaller.Type == model.Datastore {
							continue
						}
						if callersCaller.UsedAsClientByHuman {
							moreRisky := callersCommLink.HighestConfidentiality() >= model.Confidential ||
								callersCommLink.HighestIntegrity() >= model.Critical
							if moreRisky && callersCommLink.Authentication != model.TwoFactor {
								risks = append(risks, missing_authentication.CreateRisk(technicalAsset, commLink, callersCommLink, caller.Title, model.MediumImpact, model.Unlikely, true, Category()))
							}
						}
					}
				}
			}
		}
	}
	return risks
}
