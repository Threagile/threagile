package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingAuthenticationSecondFactorRule struct {
	missingAuthenticationRule *MissingAuthenticationRule
}

func NewMissingAuthenticationSecondFactorRule(missingAuthenticationRule *MissingAuthenticationRule) *MissingAuthenticationSecondFactorRule {
	return &MissingAuthenticationSecondFactorRule{missingAuthenticationRule: missingAuthenticationRule}
}

func (*MissingAuthenticationSecondFactorRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-authentication-second-factor",
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

func (r *MissingAuthenticationSecondFactorRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]

		if r.skipAsset(technicalAsset, input) {
			continue
		}

		// check each incoming data flow
		commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, commLink := range commLinks {
			caller := input.TechnicalAssets[commLink.SourceId]
			if caller.Technologies.GetAttribute(types.IsUnprotectedCommunicationsTolerated) || caller.Type == types.Datastore {
				continue
			}
			if caller.UsedAsClientByHuman {
				risks = appendRisk(input, risks, r, technicalAsset, commLink, commLink, "")
			} else if caller.Technologies.GetAttribute(types.IsTrafficForwarding) {
				// Now try to walk a call chain up (1 hop only) to find a caller's caller used by human
				callersCommLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[caller.Id]
				for _, callersCommLink := range callersCommLinks {
					callersCaller := input.TechnicalAssets[callersCommLink.SourceId]
					if callersCaller.Technologies.GetAttribute(types.IsUnprotectedCommunicationsTolerated) || callersCaller.Type == types.Datastore ||
						!callersCaller.UsedAsClientByHuman {
						continue
					}
					risks = appendRisk(input, risks, r, technicalAsset, commLink, callersCommLink, caller.Title)
				}
			}
		}
	}
		return risks, nil
}

func appendRisk(
	input *types.Model, risks []*types.Risk, r *MissingAuthenticationSecondFactorRule, 
	technicalAsset *types.TechnicalAsset, commLink *types.CommunicationLink, 
	callersCommLink *types.CommunicationLink, title string) []*types.Risk {
	moreRisky :=
		input.HighestCommunicationLinkConfidentiality(callersCommLink) >= types.Confidential ||
			input.HighestCommunicationLinkIntegrity(callersCommLink) >= types.Critical
	if moreRisky && callersCommLink.Authentication != types.TwoFactor {
		risks = append(risks, r.missingAuthenticationRule.createRisk(input, technicalAsset, commLink, callersCommLink, title, types.MediumImpact, types.Unlikely, true, r.Category()))
	}

	return risks
}

func (masf *MissingAuthenticationSecondFactorRule) skipAsset(technicalAsset *types.TechnicalAsset, input *types.Model) bool {
	if technicalAsset.OutOfScope ||
		technicalAsset.Technologies.GetAttribute(types.IsTrafficForwarding) ||
		technicalAsset.Technologies.GetAttribute(types.IsUnprotectedCommunicationsTolerated) {
		return true
	}

	if input.HighestProcessedConfidentiality(technicalAsset) < types.Confidential &&
		input.HighestProcessedIntegrity(technicalAsset) < types.Critical &&
		input.HighestProcessedAvailability(technicalAsset) < types.Critical &&
		!technicalAsset.MultiTenant {
		return true
	}

	return false
}
