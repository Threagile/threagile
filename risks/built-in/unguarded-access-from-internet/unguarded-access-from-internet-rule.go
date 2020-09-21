package unguarded_access_from_internet

import (
	"github.com/threagile/threagile/model"
	"sort"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unguarded-access-from-internet",
		Title: "Unguarded Access From Internet",
		Description: "Internet-exposed assets must be guarded by a protecting service, application, " +
			"or reverse-proxy.",
		Impact: "If this risk is unmitigated, attackers might be able to directly attack sensitive systems without any hardening components in-between " +
			"due to them being directly exposed on the internet.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Encapsulation of Technical Asset",
		Mitigation: "Encapsulate the asset behind a guarding service, application, or reverse-proxy. " +
			"For admin maintenance a bastion-host should be used as a jump-server. " +
			"For file transfer a store-and-forward-host should be used as an indirect file exchange platform.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: model.Architecture,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets (excluding " + model.LoadBalancer.String() + ") with confidentiality rating " +
			"of " + model.Confidential.String() + " (or higher) or with integrity rating of " + model.Critical.String() + " (or higher) when " +
			"accessed directly from the internet. All " +
			model.WebServer.String() + ", " + model.WebApplication.String() + ", " + model.ReverseProxy.String() + ", " + model.WAF.String() + ", and " + model.Gateway.String() + " assets are exempted from this risk when " +
			"they do not consist of custom developed code and " +
			"the data-flow only consists of HTTP or FTP protocols. Access from " + model.Monitoring.String() + " systems " +
			"as well as VPN-protected connections are exempted.",
		RiskAssessment: "The matching technical assets are at " + model.LowSeverity.String() + " risk. When either the " +
			"confidentiality rating is " + model.StrictlyConfidential.String() + " or the integrity rating " +
			"is " + model.MissionCritical.String() + ", the risk-rating is considered " + model.MediumSeverity.String() + ". " +
			"For assets with RAA values higher than 40 % the risk-rating increases.",
		FalsePositives:             "When other means of filtering client requests are applied equivalent of " + model.ReverseProxy.String() + ", " + model.WAF.String() + ", or " + model.Gateway.String() + " components.",
		ModelFailurePossibleReason: false,
		CWE:                        501,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope {
			commLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			sort.Sort(model.ByTechnicalCommunicationLinkIdSort(commLinks))
			for _, incomingAccess := range commLinks {
				if technicalAsset.Technology != model.LoadBalancer {
					if !technicalAsset.CustomDevelopedParts {
						if (technicalAsset.Technology == model.WebServer || technicalAsset.Technology == model.WebApplication || technicalAsset.Technology == model.ReverseProxy || technicalAsset.Technology == model.WAF || technicalAsset.Technology == model.Gateway) &&
							(incomingAccess.Protocol == model.HTTP || incomingAccess.Protocol == model.HTTPS) {
							continue
						}
						if technicalAsset.Technology == model.Gateway &&
							(incomingAccess.Protocol == model.FTP || incomingAccess.Protocol == model.FTPS || incomingAccess.Protocol == model.SFTP) {
							continue
						}
					}
					if model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Technology == model.Monitoring ||
						incomingAccess.VPN {
						continue
					}
					if technicalAsset.Confidentiality >= model.Confidential || technicalAsset.Integrity >= model.Critical {
						sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId]
						if sourceAsset.Internet {
							highRisk := technicalAsset.Confidentiality == model.StrictlyConfidential ||
								technicalAsset.Integrity == model.MissionCritical
							risks = append(risks, createRisk(technicalAsset, incomingAccess,
								model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId], highRisk))
						}
					}
				}
			}
		}
	}
	return risks
}

func createRisk(dataStore model.TechnicalAsset, dataFlow model.CommunicationLink,
	clientFromInternet model.TechnicalAsset, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky || dataStore.RAA > 40 {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.VeryLikely, impact),
		ExploitationLikelihood: model.VeryLikely,
		ExploitationImpact:     impact,
		Title: "<b>Unguarded Access from Internet</b> of <b>" + dataStore.Title + "</b> by <b>" +
			clientFromInternet.Title + "</b>" + " via <b>" + dataFlow.Title + "</b>",
		MostRelevantTechnicalAssetId:    dataStore.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{dataStore.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataStore.Id + "@" + clientFromInternet.Id + "@" + dataFlow.Id
	return risk
}
