package unguarded_access_from_internet

import (
	"sort"

	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/types"
)

func Rule() model.CustomRiskRule {
	return model.CustomRiskRule{
		Category:      Category,
		SupportedTags: SupportedTags,
		GenerateRisks: GenerateRisks,
	}
}

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
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets (excluding " + types.LoadBalancer.String() + ") with confidentiality rating " +
			"of " + types.Confidential.String() + " (or higher) or with integrity rating of " + types.Critical.String() + " (or higher) when " +
			"accessed directly from the internet. All " +
			types.WebServer.String() + ", " + types.WebApplication.String() + ", " + types.ReverseProxy.String() + ", " + types.WAF.String() + ", and " + types.Gateway.String() + " assets are exempted from this risk when " +
			"they do not consist of custom developed code and " +
			"the data-flow only consists of HTTP or FTP protocols. Access from " + types.Monitoring.String() + " systems " +
			"as well as VPN-protected connections are exempted.",
		RiskAssessment: "The matching technical assets are at " + types.LowSeverity.String() + " risk. When either the " +
			"confidentiality rating is " + types.StrictlyConfidential.String() + " or the integrity rating " +
			"is " + types.MissionCritical.String() + ", the risk-rating is considered " + types.MediumSeverity.String() + ". " +
			"For assets with RAA values higher than 40 % the risk-rating increases.",
		FalsePositives:             "When other means of filtering client requests are applied equivalent of " + types.ReverseProxy.String() + ", " + types.WAF.String() + ", or " + types.Gateway.String() + " components.",
		ModelFailurePossibleReason: false,
		CWE:                        501,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks(input *model.ParsedModel) []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.OutOfScope {
			commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			sort.Sort(model.ByTechnicalCommunicationLinkIdSort(commLinks))
			for _, incomingAccess := range commLinks {
				if technicalAsset.Technology != types.LoadBalancer {
					if !technicalAsset.CustomDevelopedParts {
						if (technicalAsset.Technology == types.WebServer || technicalAsset.Technology == types.WebApplication || technicalAsset.Technology == types.ReverseProxy || technicalAsset.Technology == types.WAF || technicalAsset.Technology == types.Gateway) &&
							(incomingAccess.Protocol == types.HTTP || incomingAccess.Protocol == types.HTTPS) {
							continue
						}
						if technicalAsset.Technology == types.Gateway &&
							(incomingAccess.Protocol == types.FTP || incomingAccess.Protocol == types.FTPS || incomingAccess.Protocol == types.SFTP) {
							continue
						}
					}
					if input.TechnicalAssets[incomingAccess.SourceId].Technology == types.Monitoring ||
						incomingAccess.VPN {
						continue
					}
					if technicalAsset.Confidentiality >= types.Confidential || technicalAsset.Integrity >= types.Critical {
						sourceAsset := input.TechnicalAssets[incomingAccess.SourceId]
						if sourceAsset.Internet {
							highRisk := technicalAsset.Confidentiality == types.StrictlyConfidential ||
								technicalAsset.Integrity == types.MissionCritical
							risks = append(risks, createRisk(technicalAsset, incomingAccess,
								input.TechnicalAssets[incomingAccess.SourceId], highRisk))
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
	impact := types.LowImpact
	if moreRisky || dataStore.RAA > 40 {
		impact = types.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(types.VeryLikely, impact),
		ExploitationLikelihood: types.VeryLikely,
		ExploitationImpact:     impact,
		Title: "<b>Unguarded Access from Internet</b> of <b>" + dataStore.Title + "</b> by <b>" +
			clientFromInternet.Title + "</b>" + " via <b>" + dataFlow.Title + "</b>",
		MostRelevantTechnicalAssetId:    dataStore.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{dataStore.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataStore.Id + "@" + clientFromInternet.Id + "@" + dataFlow.Id
	return risk
}
