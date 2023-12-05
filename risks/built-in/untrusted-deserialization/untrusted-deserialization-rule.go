package untrusted_deserialization

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "untrusted-deserialization",
		Title: "Untrusted Deserialization",
		Description: "When a technical asset accepts data in a specific serialized form (like Java or .NET serialization), " +
			"Untrusted Deserialization risks might arise." +
			"<br><br>See <a href=\"https://christian-schneider.net/JavaDeserializationSecurityFAQ.html\">https://christian-schneider.net/JavaDeserializationSecurityFAQ.html</a> " +
			"for more details.",
		Impact:     "If this risk is unmitigated, attackers might be able to execute code on target systems by exploiting untrusted deserialization endpoints.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
		Action:     "Prevention of Deserialization of Untrusted Data",
		Mitigation: "Try to avoid the deserialization of untrusted data (even of data within the same trust-boundary as long as " +
			"it is sent across a remote connection) in order to stay safe from Untrusted Deserialization vulnerabilities. " +
			"Alternatively a strict whitelisting approach of the classes/types/values to deserialize might help as well. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Architecture,
		STRIDE:         model.Tampering,
		DetectionLogic: "In-scope technical assets accepting serialization data formats (including EJB and RMI protocols).",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed and stored.",
		FalsePositives: "Fully trusted (i.e. cryptographically signed or similar) data deserialized can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        502,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		hasOne, acrossTrustBoundary := false, false
		commLinkTitle := ""
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == model.Serialization {
				hasOne = true
			}
		}
		if technicalAsset.Technology == model.EJB {
			hasOne = true
		}
		// check for any incoming IIOP and JRMP protocols
		for _, commLink := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			if commLink.Protocol == model.IIOP || commLink.Protocol == model.IIOP_encrypted ||
				commLink.Protocol == model.JRMP || commLink.Protocol == model.JRMP_encrypted {
				hasOne = true
				if commLink.IsAcrossTrustBoundaryNetworkOnly() {
					acrossTrustBoundary = true
					commLinkTitle = commLink.Title
				}
			}
		}
		if hasOne {
			risks = append(risks, createRisk(technicalAsset, acrossTrustBoundary, commLinkTitle))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, acrossTrustBoundary bool, commLinkTitle string) model.Risk {
	title := "<b>Untrusted Deserialization</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.HighImpact
	likelihood := model.Likely
	if acrossTrustBoundary {
		likelihood = model.VeryLikely
		title += " across a trust boundary (at least via communication link <b>" + commLinkTitle + "</b>)"
	}
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.VeryHighImpact
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
