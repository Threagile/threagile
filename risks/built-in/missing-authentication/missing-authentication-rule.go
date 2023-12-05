package missing_authentication

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "missing-authentication",
		Title:       "Missing Authentication",
		Description: "Technical assets (especially multi-tenant systems) should authenticate incoming requests when the asset processes or stores sensitive data. ",
		Impact:      "If this risk is unmitigated, attackers might be able to access or modify sensitive data in an unauthenticated way.",
		ASVS:        "V2 - Authentication Verification Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		Action:      "Authentication of Incoming Requests",
		Mitigation: "Apply an authentication method to the technical asset. To protect highly sensitive data consider " +
			"the use of two-factor authentication for human users.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: model.Architecture,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets (except " + model.LoadBalancer.String() + ", " + model.ReverseProxy.String() + ", " + model.ServiceRegistry.String() + ", " + model.WAF.String() + ", " + model.IDS.String() + ", and " + model.IPS.String() + " and in-process calls) should authenticate incoming requests when the asset processes or stores " +
			"sensitive data. This is especially the case for all multi-tenant assets (there even non-sensitive ones).",
		RiskAssessment: "The risk rating (medium or high) " +
			"depends on the sensitivity of the data sent across the communication link. Monitoring callers are exempted from this risk.",
		FalsePositives: "Technical assets which do not process requests regarding functionality or data linked to end-users (customers) " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        306,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technology == model.LoadBalancer ||
			technicalAsset.Technology == model.ReverseProxy || technicalAsset.Technology == model.ServiceRegistry || technicalAsset.Technology == model.WAF || technicalAsset.Technology == model.IDS || technicalAsset.Technology == model.IPS {
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
				highRisk := commLink.HighestConfidentiality() == model.StrictlyConfidential ||
					commLink.HighestIntegrity() == model.MissionCritical
				lowRisk := commLink.HighestConfidentiality() <= model.Internal &&
					commLink.HighestIntegrity() == model.Operational
				impact := model.MediumImpact
				if highRisk {
					impact = model.HighImpact
				} else if lowRisk {
					impact = model.LowImpact
				}
				if commLink.Authentication == model.NoneAuthentication && !commLink.Protocol.IsProcessLocal() {
					risks = append(risks, CreateRisk(technicalAsset, commLink, commLink, "", impact, model.Likely, false, Category()))
				}
			}
		}
	}
	return risks
}

func CreateRisk(technicalAsset model.TechnicalAsset, incomingAccess, incomingAccessOrigin model.CommunicationLink, hopBetween string,
	impact model.RiskExploitationImpact, likelihood model.RiskExploitationLikelihood, twoFactor bool, category model.RiskCategory) model.Risk {
	factorString := ""
	if twoFactor {
		factorString = "Two-Factor "
	}
	if len(hopBetween) > 0 {
		hopBetween = "forwarded via <b>" + hopBetween + "</b> "
	}
	risk := model.Risk{
		Category:               category,
		Severity:               model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing " + factorString + "Authentication</b> covering communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + model.ParsedModelRoot.TechnicalAssets[incomingAccessOrigin.SourceId].Title + "</b> " + hopBetween +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + incomingAccess.Id + "@" + model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
