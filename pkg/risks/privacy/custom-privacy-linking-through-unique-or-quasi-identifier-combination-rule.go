package privacy

import (
	"sort"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

type LinkingThroughUniqueOrQuasiIdCombination struct{}

func NewLinkingThroughUniqueOrQuasiIdCombination() *LinkingThroughUniqueOrQuasiIdCombination {
	return &LinkingThroughUniqueOrQuasiIdCombination{}
}

func (*LinkingThroughUniqueOrQuasiIdCombination) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "linking-through-unique-or-quasi-id-combination",
		Title:                      "Linking Through Unique Or Quasi Id Combination",
		Description:                "A technical asset can link data to a data subject due to presence of personal information such as a direct identifier (e.g. SSN) or a set of quasi-identifiers (e.g. Birthdate, Zip Code, Gender) of size greater than some threshold (3). In such cases, Linking Through Unique Or Quasi Identifier Combination risk can exist. Quasi-identifiers are combinations of data that, while not unique on their own, can collectively identify a data subject.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check LINDDUN threat category Linking (L.1.1, L.2.1.1, L.2.1.2)",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Implement data minimization principles.",
		Mitigation:                 "Avoid non-essential unique identifiers (by replacing them with secure, non-sensitive tokens). Limit collected attributes to only necessary ones, and analyze attribute combinations to prioritize mitigation of high-risk quasi-identifiers. Apply data minimization.",
		Check:                      "Are Linkability concerns as described from LINDDUN threat trees (L.1.1, L.2.1.*) addressed?",
		Function:                   types.Architecture,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Rule identifies risks where: (1) A technical asset can link data subjects using Direct Identifiers (DI), (2) A technical asset or the system as a whole can link data subjects using a combination of Quasi-Identifiers (QDI) that exceed a threshold (threshold == 3).",
		RiskAssessment:             types.MediumSeverity.String(),
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*LinkingThroughUniqueOrQuasiIdCombination) SupportedTags() []string {
	return []string{"linking-through-unique-or-quasi-id-combination"}
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func (r *LinkingThroughUniqueOrQuasiIdCombination) GenerateRisks(model *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	quasiIdentifierThreshold := 3
	if model.Deidentified {
		return risks, nil
	}
	modelLevelQuasiIDList := make([]string, 0)
	for _, technicalAsset := range model.TechnicalAssets {
		if technicalAsset.Technologies.HasAuthenticatingTechnology() {
			continue
		}
		DIList := make([]string, 0)
		QuasiIDList := make([]string, 0)
		for _, commLink := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			for _, dataAssetID := range commLink.DataAssetsSent {
				dataAsset := model.DataAssets[dataAssetID]
				if dataAsset.PINameType.IsDI() && !contains(DIList, dataAsset.Id) {
					DIList = append(DIList, dataAsset.Id)
				} else if dataAsset.PINameType.IsQDI() {
					if !contains(QuasiIDList, dataAsset.Id) {
						QuasiIDList = append(QuasiIDList, dataAsset.Id)
					}
					if !contains(modelLevelQuasiIDList, dataAsset.Id) {
						modelLevelQuasiIDList = append(modelLevelQuasiIDList, dataAsset.Id)
					}
				}
			}
		}

		for _, dataAsset := range model.DataAssets {
			if contains(technicalAsset.DataAssetsStored, dataAsset.Id) || contains(technicalAsset.DataAssetsProcessed, dataAsset.Id) {
				if dataAsset.PINameType.IsDI() && !contains(DIList, dataAsset.Id) {
					DIList = append(DIList, dataAsset.Id)
				} else if dataAsset.PINameType.IsQDI() {
					if !contains(QuasiIDList, dataAsset.Id) {
						QuasiIDList = append(QuasiIDList, dataAsset.Id)
					}
					if !contains(modelLevelQuasiIDList, dataAsset.Id) {
						modelLevelQuasiIDList = append(modelLevelQuasiIDList, dataAsset.Id)
					}
				}
			}
		}
		if len(DIList) > 0 {
			sort.Strings(DIList)
			risks = r.createRisks(risks, technicalAsset.Id, "Linkable Direct Identifiers at technical asset-level ID: "+technicalAsset.Id+" - PI ID(s): "+strings.Join(DIList, ", "), DIList)
		}
		if len(QuasiIDList) >= quasiIdentifierThreshold {
			sort.Strings(QuasiIDList)
			risks = r.createRisks(risks, technicalAsset.Id, "Linkable "+strconv.Itoa(len(QuasiIDList))+"(>=5) Quasi-Identifiers at technical asset-level ID: "+technicalAsset.Id+" - PI ID(s): "+strings.Join(QuasiIDList, ", "), QuasiIDList)
		}
	}
	if len(modelLevelQuasiIDList) >= quasiIdentifierThreshold {
		sort.Strings(modelLevelQuasiIDList)
		risks = r.createRisks(risks, "", "Linkable Quasi-Identifiers at model-level: PI ID(s): "+strings.Join(modelLevelQuasiIDList, ", "), modelLevelQuasiIDList)
	}

	return risks, nil
}

func (r *LinkingThroughUniqueOrQuasiIdCombination) createRisks(risks []*types.Risk, techAssetID string, titleStr string, daList []string) []*types.Risk {
	title := "<b>Linking Through Unique Or Quasi-Identifier Combination</b> risk: <b> " + titleStr + "</b>"
	for _, dataAssetID := range daList {
		risks = append(risks, r.createRisk(techAssetID, title, dataAssetID))
	}
	return risks
}

func (r *LinkingThroughUniqueOrQuasiIdCombination) createRisk(technicalAssetId string, title string, daID string) *types.Risk {
	risk := &types.Risk{
		CategoryId:                  r.Category().ID,
		Severity:                    types.CalculateSeverity(types.VeryLikely, types.MediumImpact),
		ExploitationLikelihood:      types.VeryLikely,
		ExploitationImpact:          types.MediumImpact,
		Title:                       title,
		MostRelevantDataAssetId:     daID,
		DataBreachProbability:       types.Possible,
		DataBreachTechnicalAssetIDs: []string{technicalAssetId},
	}
	if len(technicalAssetId) != 0 {
		risk.MostRelevantTechnicalAssetId = technicalAssetId
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAssetId + "@" + daID
	return risk
}
