package unguarded_direct_datastore_access

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "unguarded-direct-datastore-access",
		Title:       "Unguarded Direct Datastore Access",
		Description: "Datastores accessed across trust boundaries must be guarded by some protecting service or application.",
		Impact:      "If this risk is unmitigated, attackers might be able to directly attack sensitive datastores without any protecting components in-between.",
		ASVS:        "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:      "Encapsulation of Datastore",
		Mitigation:  "Encapsulate the datastore access behind a guarding service or application.",
		Check:       "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:    model.Architecture,
		STRIDE:      model.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets of type " + model.Datastore.String() + " (except " + model.IdentityStoreLDAP.String() + " when accessed from " + model.IdentityProvider.String() + " and " + model.FileServer.String() + " when accessed via file transfer protocols) with confidentiality rating " +
			"of " + model.Confidential.String() + " (or higher) or with integrity rating of " + model.Critical.String() + " (or higher) " +
			"which have incoming data-flows from assets outside across a network trust-boundary. DevOps config and deployment access is excluded from this risk.", // TODO new rule "missing bastion host"?
		RiskAssessment: "The matching technical assets are at " + model.LowSeverity.String() + " risk. When either the " +
			"confidentiality rating is " + model.StrictlyConfidential.String() + " or the integrity rating " +
			"is " + model.MissionCritical.String() + ", the risk-rating is considered " + model.MediumSeverity.String() + ". " +
			"For assets with RAA values higher than 40 % the risk-rating increases.",
		FalsePositives:             "When the caller is considered fully trusted as if it was part of the datastore itself.",
		ModelFailurePossibleReason: false,
		CWE:                        501,
	}
}

func SupportedTags() []string {
	return []string{}
}

// check for datastores that should not be accessed directly across trust boundaries
func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Type == model.Datastore {
			for _, incomingAccess := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId]
				if (technicalAsset.Technology == model.IdentityStoreLDAP || technicalAsset.Technology == model.IdentityStoreDatabase) &&
					sourceAsset.Technology == model.IdentityProvider {
					continue
				}
				if technicalAsset.Confidentiality >= model.Confidential || technicalAsset.Integrity >= model.Critical {
					if incomingAccess.IsAcrossTrustBoundaryNetworkOnly() && !FileServerAccessViaFTP(technicalAsset, incomingAccess) &&
						incomingAccess.Usage != model.DevOps && !model.IsSharingSameParentTrustBoundary(technicalAsset, sourceAsset) {
						highRisk := technicalAsset.Confidentiality == model.StrictlyConfidential ||
							technicalAsset.Integrity == model.MissionCritical
						risks = append(risks, createRisk(technicalAsset, incomingAccess,
							model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId], highRisk))
					}
				}
			}
		}
	}
	return risks
}

func FileServerAccessViaFTP(technicalAsset model.TechnicalAsset, incomingAccess model.CommunicationLink) bool {
	return technicalAsset.Technology == model.FileServer &&
		(incomingAccess.Protocol == model.FTP || incomingAccess.Protocol == model.FTPS || incomingAccess.Protocol == model.SFTP)
}

func createRisk(dataStore model.TechnicalAsset, dataFlow model.CommunicationLink, clientOutsideTrustBoundary model.TechnicalAsset, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky || dataStore.RAA > 40 {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood: model.Likely,
		ExploitationImpact:     impact,
		Title: "<b>Unguarded Direct Datastore Access</b> of <b>" + dataStore.Title + "</b> by <b>" +
			clientOutsideTrustBoundary.Title + "</b> via <b>" + dataFlow.Title + "</b>",
		MostRelevantTechnicalAssetId:    dataStore.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{dataStore.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataFlow.Id + "@" + clientOutsideTrustBoundary.Id + "@" + dataStore.Id
	return risk
}
