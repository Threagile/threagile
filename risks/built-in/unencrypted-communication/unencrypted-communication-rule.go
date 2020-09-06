package unencrypted_communication

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unencrypted-communication",
		Title: "Unencrypted Communication",
		Description: "Due to the confidentiality and/or integrity rating of the data assets transferred over the " +
			"communication link this connection must be encrypted.",
		Impact:     "If this risk is unmitigated, network attackers might be able to to eavesdrop on unencrypted sensitive data sent between components.",
		ASVS:       "V9 - Communication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
		Action:     "Encryption of Communication Links",
		Mitigation: "Apply transport layer encryption to the communication link.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Operations,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "Unencrypted technical communication links of in-scope technical assets (excluding " + model.Monitoring.String() + " traffic as well as " + model.LocalFileAccess.String() + " and " + model.InProcessLibraryCall.String() + ") " +
			"transferring sensitive data.", // TODO more detailed text required here
		RiskAssessment: "Depending on the confidentiality rating of the transferred data-assets either medium or high risk.",
		FalsePositives: "When all sensitive data sent over the communication link is already fully encrypted on document or data level. " +
			"Also intra-container/pod communication can be considered false positive when container orchestration platform handles encryption.",
		ModelFailurePossibleReason: false,
		CWE:                        319,
	}
}

func SupportedTags() []string {
	return []string{}
}

// check for communication links that should be encrypted due to their confidentiality and/or integrity
func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			transferringAuthData := dataFlow.Authentication != model.NoneAuthentication
			sourceAsset := model.ParsedModelRoot.TechnicalAssets[dataFlow.SourceId]
			targetAsset := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
			if !technicalAsset.OutOfScope || !sourceAsset.OutOfScope {
				if !dataFlow.Protocol.IsEncrypted() && !dataFlow.Protocol.IsProcessLocal() &&
					!sourceAsset.Technology.IsUnprotectedCommsTolerated() &&
					!targetAsset.Technology.IsUnprotectedCommsTolerated() {
					addedOne := false
					for _, sentDataAsset := range dataFlow.DataAssetsSent {
						dataAsset := model.ParsedModelRoot.DataAssets[sentDataAsset]
						if isHighSensitivity(dataAsset) || transferringAuthData {
							risks = append(risks, createRisk(technicalAsset, dataFlow, true, transferringAuthData))
							addedOne = true
							break
						} else if !dataFlow.VPN && isMediumSensitivity(dataAsset) {
							risks = append(risks, createRisk(technicalAsset, dataFlow, false, transferringAuthData))
							addedOne = true
							break
						}
					}
					if !addedOne {
						for _, receivedDataAsset := range dataFlow.DataAssetsReceived {
							dataAsset := model.ParsedModelRoot.DataAssets[receivedDataAsset]
							if isHighSensitivity(dataAsset) || transferringAuthData {
								risks = append(risks, createRisk(technicalAsset, dataFlow, true, transferringAuthData))
								break
							} else if !dataFlow.VPN && isMediumSensitivity(dataAsset) {
								risks = append(risks, createRisk(technicalAsset, dataFlow, false, transferringAuthData))
								break
							}
						}
					}
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, dataFlow model.CommunicationLink, highRisk bool, transferringAuthData bool) model.Risk {
	impact := model.MediumImpact
	if highRisk {
		impact = model.HighImpact
	}
	target := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
	title := "<b>Unencrypted Communication</b> named <b>" + dataFlow.Title + "</b> between <b>" + technicalAsset.Title + "</b> and <b>" + target.Title + "</b>"
	if transferringAuthData {
		title += " transferring authentication data (like credentials, token, session-id, etc.)"
	}
	if dataFlow.VPN {
		title += " (even VPN-protected connections need to encrypt their data in-transit when confidentiality is " +
			"rated " + model.StrictlyConfidential.String() + " or integrity is rated " + model.MissionCritical.String() + ")"
	}
	likelihood := model.Unlikely
	if dataFlow.IsAcrossTrustBoundaryNetworkOnly() {
		likelihood = model.Likely
	}
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataFlow.Id + "@" + technicalAsset.Id + "@" + target.Id
	return risk
}

func isHighSensitivity(dataAsset model.DataAsset) bool {
	return dataAsset.Confidentiality == model.StrictlyConfidential || dataAsset.Integrity == model.MissionCritical
}

func isMediumSensitivity(dataAsset model.DataAsset) bool {
	return dataAsset.Confidentiality == model.Confidential || dataAsset.Integrity == model.Critical
}
