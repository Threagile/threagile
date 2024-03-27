package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type MissingAuthenticationSecondFactorRule struct {
	missingAuthenticationRule *MissingAuthenticationRule
}

func NewMissingAuthenticationSecondFactorRule(missingAuthenticationRule *MissingAuthenticationRule) *MissingAuthenticationSecondFactorRule {
	return &MissingAuthenticationSecondFactorRule{missingAuthenticationRule: missingAuthenticationRule}
}

func (*MissingAuthenticationSecondFactorRule) Category() types.RiskCategory {
	return types.RiskCategory{
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
		Function: types.BusinessSide,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets (except " + types.LoadBalancer + ", " + types.ReverseProxy + ", " + types.WAF + ", " + types.IDS + ", and " + types.IPS + ") should authenticate incoming requests via two-factor authentication (2FA) " +
			"when the asset processes or stores highly sensitive data (in terms of confidentiality, integrity, and availability) and is accessed by a client used by a human user.",
		RiskAssessment: types.MediumSeverity.String(),
		FalsePositives: "Technical assets which do not process requests regarding functionality or data linked to end-users (customers) " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        308,
	}
}

func (*MissingAuthenticationSecondFactorRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingAuthenticationSecondFactorRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope ||
			technicalAsset.Technologies.GetAttribute(types.IsTrafficForwarding) ||
			technicalAsset.Technologies.GetAttribute(types.IsUnprotectedCommunicationsTolerated) {
			continue
		}
		if technicalAsset.HighestProcessedConfidentiality(input) >= types.Confidential ||
			technicalAsset.HighestProcessedIntegrity(input) >= types.Critical ||
			technicalAsset.HighestProcessedAvailability(input) >= types.Critical ||
			technicalAsset.MultiTenant {
			// check each incoming data flow
			commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, commLink := range commLinks {
				caller := input.TechnicalAssets[commLink.SourceId]
				if caller.Technologies.GetAttribute(types.IsUnprotectedCommunicationsTolerated) || caller.Type == types.Datastore {
					continue
				}
				if caller.UsedAsClientByHuman {
					moreRisky := commLink.HighestConfidentiality(input) >= types.Confidential ||
						commLink.HighestIntegrity(input) >= types.Critical
					if moreRisky && commLink.Authentication != types.TwoFactor {
						risks = append(risks, r.missingAuthenticationRule.createRisk(input, technicalAsset, commLink, commLink, "", types.MediumImpact, types.Unlikely, true, r.Category()))
					}
				} else if caller.Technologies.GetAttribute(types.IsTrafficForwarding) {
					// Now try to walk a call chain up (1 hop only) to find a caller's caller used by human
					callersCommLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[caller.Id]
					for _, callersCommLink := range callersCommLinks {
						callersCaller := input.TechnicalAssets[callersCommLink.SourceId]
						if callersCaller.Technologies.GetAttribute(types.IsUnprotectedCommunicationsTolerated) || callersCaller.Type == types.Datastore {
							continue
						}
						if callersCaller.UsedAsClientByHuman {
							moreRisky := callersCommLink.HighestConfidentiality(input) >= types.Confidential ||
								callersCommLink.HighestIntegrity(input) >= types.Critical
							if moreRisky && callersCommLink.Authentication != types.TwoFactor {
								risks = append(risks, r.missingAuthenticationRule.createRisk(input, technicalAsset, commLink, callersCommLink, caller.Title, types.MediumImpact, types.Unlikely, true, r.Category()))
							}
						}
					}
				}
			}
		}
	}
	return risks
}
