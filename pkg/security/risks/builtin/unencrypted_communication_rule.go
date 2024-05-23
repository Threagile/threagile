package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type UnencryptedCommunicationRule struct{}

func NewUnencryptedCommunicationRule() *UnencryptedCommunicationRule {
	return &UnencryptedCommunicationRule{}
}

func (*UnencryptedCommunicationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unencrypted-communication",
		Title: "Unencrypted Communication",
		Description: "Due to the confidentiality and/or integrity rating of the data assets transferred over the " +
			"communication link this connection must be encrypted.",
		Impact:     "If this risk is unmitigated, network attackers might be able to to eavesdrop on unencrypted sensitive data sent between components.",
		ASVS:       "V9 - Communication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
		Action:     "Encryption of Communication Links",
		Mitigation: "Apply transport layer encryption to the communication link.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   types.Operations,
		STRIDE:     types.InformationDisclosure,
		DetectionLogic: "Unencrypted technical communication links of in-scope technical assets (excluding " + types.Monitoring + " traffic as well as " + types.LocalFileAccess.String() + " and " + types.InProcessLibraryCall.String() + ") " +
			"transferring sensitive data.", // TODO more detailed text required here
		RiskAssessment: "Depending on the confidentiality rating of the transferred data-assets either medium or high risk.",
		FalsePositives: "When all sensitive data sent over the communication link is already fully encrypted on document or data level. " +
			"Also intra-container/pod communication can be considered false positive when container orchestration platform handles encryption.",
		ModelFailurePossibleReason: false,
		CWE:                        319,
	}
}

func (*UnencryptedCommunicationRule) SupportedTags() []string {
	return []string{}
}

// check for communication links that should be encrypted due to their confidentiality and/or integrity

func (r *UnencryptedCommunicationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			transferringAuthData := dataFlow.Authentication != types.NoneAuthentication
			sourceAsset := input.TechnicalAssets[dataFlow.SourceId]
			targetAsset := input.TechnicalAssets[dataFlow.TargetId]
			if !technicalAsset.OutOfScope || !sourceAsset.OutOfScope {
				if !dataFlow.Protocol.IsEncrypted() && !dataFlow.Protocol.IsProcessLocal() &&
					!sourceAsset.Technologies.GetAttribute(types.IsUnprotectedCommunicationsTolerated) &&
					!targetAsset.Technologies.GetAttribute(types.IsUnprotectedCommunicationsTolerated) {
					addedOne := false
					for _, sentDataAsset := range dataFlow.DataAssetsSent {
						dataAsset := input.DataAssets[sentDataAsset]
						if isHighSensitivity(dataAsset) || transferringAuthData {
							risks = append(risks, r.createRisk(input, technicalAsset, dataFlow, true, transferringAuthData))
							addedOne = true
							break
						} else if !dataFlow.VPN && isMediumSensitivity(dataAsset) {
							risks = append(risks, r.createRisk(input, technicalAsset, dataFlow, false, transferringAuthData))
							addedOne = true
							break
						}
					}
					if !addedOne {
						for _, receivedDataAsset := range dataFlow.DataAssetsReceived {
							dataAsset := input.DataAssets[receivedDataAsset]
							if isHighSensitivity(dataAsset) || transferringAuthData {
								risks = append(risks, r.createRisk(input, technicalAsset, dataFlow, true, transferringAuthData))
								break
							} else if !dataFlow.VPN && isMediumSensitivity(dataAsset) {
								risks = append(risks, r.createRisk(input, technicalAsset, dataFlow, false, transferringAuthData))
								break
							}
						}
					}
				}
			}
		}
	}
	return risks, nil
}

func (r *UnencryptedCommunicationRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, dataFlow *types.CommunicationLink, highRisk bool, transferringAuthData bool) *types.Risk {
	impact := types.MediumImpact
	if highRisk {
		impact = types.HighImpact
	}
	target := input.TechnicalAssets[dataFlow.TargetId]
	title := "<b>Unencrypted Communication</b> named <b>" + dataFlow.Title + "</b> between <b>" + technicalAsset.Title + "</b> and <b>" + target.Title + "</b>"
	if transferringAuthData {
		title += " transferring authentication data (like credentials, token, session-id, etc.)"
	}
	if dataFlow.VPN {
		title += " (even VPN-protected connections need to encrypt their data in-transit when confidentiality is " +
			"rated " + types.StrictlyConfidential.String() + " or integrity is rated " + types.MissionCritical.String() + ")"
	}
	likelihood := types.Unlikely
	if dataFlow.IsAcrossTrustBoundaryNetworkOnly(input) {
		likelihood = types.Likely
	}
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + dataFlow.Id + "@" + technicalAsset.Id + "@" + target.Id
	return risk
}

func isHighSensitivity(dataAsset *types.DataAsset) bool {
	return dataAsset.Confidentiality == types.StrictlyConfidential || dataAsset.Integrity == types.MissionCritical
}

func isMediumSensitivity(dataAsset *types.DataAsset) bool {
	return dataAsset.Confidentiality == types.Confidential || dataAsset.Integrity == types.Critical
}
