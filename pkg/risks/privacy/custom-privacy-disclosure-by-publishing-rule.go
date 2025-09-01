package privacy

import (
	"github.com/threagile/threagile/pkg/types"
)

type DisclosureByPublishingRule struct{}

func NewDisclosureByPublishingRule() *DisclosureByPublishingRule {
	return &DisclosureByPublishingRule{}
}

func (r DisclosureByPublishingRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "disclosure-by-publishing",
		Title:                      "Disclosure By Publishing",
		Description:                "Risk of Disclosure By Publishing happens when personal information is published more broadly or shared to external assets than what the requirement states or without a formal disclosure agreement in place. For example, making personal information publicly available intentionally (doxing) or unintentionally.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check NIST Privacy Controls Framework",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Obtain users' permission before publishing their data.",
		Mitigation:                 "Confirm the necessity of sharing personal data and ensure genuine access requirements for the parties who will receive it. Finally, obtain discosure agreement with the data subject.",
		Check:                      "Are Data Disclosure concerns as described from LINDDUN threat trees (DD.4.2) addressed?",
		Function:                   types.Architecture,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Rule identifies risks where personal data (PI) is: (1) Sent to external entities, (2) Stored in internet-facing technical assets. These situations are flagged as risks because they may lead to unintended disclosure of personal data.",
		RiskAssessment:             "Depends on the type of data assets involved i.e. Personal Information (PI) or not",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*DisclosureByPublishingRule) SupportedTags() []string {
	return []string{"disclosure-by-publishing"}
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func (r *DisclosureByPublishingRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {

	risks := make([]*types.Risk, 0)

	if parsedModel.PublicDisclosureSigned {
		return risks, nil
	}

	for _, ta := range parsedModel.TechnicalAssets {
		if ta.Type == types.ExternalEntity || ta.Internet {
			setAffectedPI := make([]string, 0)

			commLinks := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[ta.Id]

			for _, commLink := range commLinks {
				PIs_sent := parsedModel.GetPI(commLink.DataAssetsSent)
				setAffectedPI = append(setAffectedPI, PIs_sent...)
			}

			PIs_stored := parsedModel.GetPI(ta.DataAssetsStored)
			setAffectedPI = append(setAffectedPI, PIs_stored...)
			setAffectedPI = removeDuplicates(setAffectedPI)

			for _, pi := range setAffectedPI {
				risks = append(risks, r.createRisk(ta, parsedModel.DataAssets[pi], pi))
			}
		}
	}

	return risks, nil
}

func (r *DisclosureByPublishingRule) createRisk(technicalAsset *types.TechnicalAsset, dataAsset *types.DataAsset, titleMod string) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.RiskSeverity(types.MediumImpact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Disclosure by publishing</b> risk at <b> " + technicalAsset.Title + "</b> with source: " + dataAsset.Title + "</b> with PI: " + titleMod,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
		MostRelevantDataAssetId:      dataAsset.Id,
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
