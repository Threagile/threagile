package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type UntrustedDeserializationRule struct{}

func NewUntrustedDeserializationRule() *UntrustedDeserializationRule {
	return &UntrustedDeserializationRule{}
}

func (*UntrustedDeserializationRule) Category() types.RiskCategory {
	return types.RiskCategory{
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
		Function:       types.Architecture,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope technical assets accepting serialization data formats (including EJB and RMI protocols).",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Fully trusted (i.e. cryptographically signed or similar) data deserialized can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        502,
	}
}

func (*UntrustedDeserializationRule) SupportedTags() []string {
	return []string{}
}

func (r *UntrustedDeserializationRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		hasOne, acrossTrustBoundary := false, false
		commLinkTitle := ""
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == types.Serialization {
				hasOne = true
			}
		}
		if technicalAsset.Technology == types.EJB {
			hasOne = true
		}
		// check for any incoming IIOP and JRMP protocols
		for _, commLink := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			if commLink.Protocol == types.IIOP || commLink.Protocol == types.IiopEncrypted ||
				commLink.Protocol == types.JRMP || commLink.Protocol == types.JrmpEncrypted {
				hasOne = true
				if commLink.IsAcrossTrustBoundaryNetworkOnly(input) {
					acrossTrustBoundary = true
					commLinkTitle = commLink.Title
				}
			}
		}
		if hasOne {
			risks = append(risks, r.createRisk(input, technicalAsset, acrossTrustBoundary, commLinkTitle))
		}
	}
	return risks
}

func (r *UntrustedDeserializationRule) createRisk(parsedModel *types.ParsedModel, technicalAsset types.TechnicalAsset, acrossTrustBoundary bool, commLinkTitle string) types.Risk {
	title := "<b>Untrusted Deserialization</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.HighImpact
	likelihood := types.Likely
	if acrossTrustBoundary {
		likelihood = types.VeryLikely
		title += " across a trust boundary (at least via communication link <b>" + commLinkTitle + "</b>)"
	}
	if technicalAsset.HighestConfidentiality(parsedModel) == types.StrictlyConfidential ||
		technicalAsset.HighestIntegrity(parsedModel) == types.MissionCritical ||
		technicalAsset.HighestAvailability(parsedModel) == types.MissionCritical {
		impact = types.VeryHighImpact
	}
	risk := types.Risk{
		CategoryId:                   r.Category().Id,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
