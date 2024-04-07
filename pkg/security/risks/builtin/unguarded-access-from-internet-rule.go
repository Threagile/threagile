package builtin

import (
	"sort"

	"github.com/threagile/threagile/pkg/security/types"
)

type UnguardedAccessFromInternetRule struct{}

func NewUnguardedAccessFromInternetRule() *UnguardedAccessFromInternetRule {
	return &UnguardedAccessFromInternetRule{}
}

func (*UnguardedAccessFromInternetRule) Category() types.RiskCategory {
	return types.RiskCategory{
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
		DetectionLogic: "In-scope technical assets (excluding " + types.LoadBalancer + ") with confidentiality rating " +
			"of " + types.Confidential.String() + " (or higher) or with integrity rating of " + types.Critical.String() + " (or higher) when " +
			"accessed directly from the internet. All " +
			types.WebServer + ", " + types.WebApplication + ", " + types.ReverseProxy + ", " + types.WAF + ", and " + types.Gateway + " assets are exempted from this risk when " +
			"they do not consist of custom developed code and " +
			"the data-flow only consists of HTTP or FTP protocols. Access from " + types.Monitoring + " systems " +
			"as well as VPN-protected connections are exempted.",
		RiskAssessment: "The matching technical assets are at " + types.LowSeverity.String() + " risk. When either the " +
			"confidentiality rating is " + types.StrictlyConfidential.String() + " or the integrity rating " +
			"is " + types.MissionCritical.String() + ", the risk-rating is considered " + types.MediumSeverity.String() + ". " +
			"For assets with RAA values higher than 40 % the risk-rating increases.",
		FalsePositives:             "When other means of filtering client requests are applied equivalent of " + types.ReverseProxy + ", " + types.WAF + ", or " + types.Gateway + " components.",
		ModelFailurePossibleReason: false,
		CWE:                        501,
	}
}

func (*UnguardedAccessFromInternetRule) SupportedTags() []string {
	return []string{}
}

func (r *UnguardedAccessFromInternetRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.OutOfScope {
			commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			sort.Sort(types.ByTechnicalCommunicationLinkIdSort(commLinks))
			for _, incomingAccess := range commLinks {
				if !technicalAsset.Technologies.GetAttribute(types.LoadBalancer) {
					if !technicalAsset.CustomDevelopedParts {
						if technicalAsset.Technologies.GetAttribute(types.IsHTTPInternetAccessOK) && (incomingAccess.Protocol == types.HTTP || incomingAccess.Protocol == types.HTTPS) {
							continue
						}
						if technicalAsset.Technologies.GetAttribute(types.IsFTPInternetAccessOK) && (incomingAccess.Protocol == types.FTP || incomingAccess.Protocol == types.FTPS || incomingAccess.Protocol == types.SFTP) {
							continue
						}
					}
					if input.TechnicalAssets[incomingAccess.SourceId].Technologies.GetAttribute(types.Monitoring) ||
						incomingAccess.VPN {
						continue
					}
					if technicalAsset.Confidentiality >= types.Confidential || technicalAsset.Integrity >= types.Critical {
						sourceAsset := input.TechnicalAssets[incomingAccess.SourceId]
						if sourceAsset.Internet {
							highRisk := technicalAsset.Confidentiality == types.StrictlyConfidential ||
								technicalAsset.Integrity == types.MissionCritical
							risks = append(risks, r.createRisk(technicalAsset, incomingAccess,
								input.TechnicalAssets[incomingAccess.SourceId], highRisk))
						}
					}
				}
			}
		}
	}
	return risks
}

func (r *UnguardedAccessFromInternetRule) createRisk(dataStore *types.TechnicalAsset, dataFlow *types.CommunicationLink,
	clientFromInternet *types.TechnicalAsset, moreRisky bool) types.Risk {
	impact := types.LowImpact
	if moreRisky || dataStore.RAA > 40 {
		impact = types.MediumImpact
	}
	risk := types.Risk{
		CategoryId:             r.Category().Id,
		Severity:               types.CalculateSeverity(types.VeryLikely, impact),
		ExploitationLikelihood: types.VeryLikely,
		ExploitationImpact:     impact,
		Title: "<b>Unguarded Access from Internet</b> of <b>" + dataStore.Title + "</b> by <b>" +
			clientFromInternet.Title + "</b>" + " via <b>" + dataFlow.Title + "</b>",
		MostRelevantTechnicalAssetId:    dataStore.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{dataStore.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + dataStore.Id + "@" + clientFromInternet.Id + "@" + dataFlow.Id
	return risk
}
