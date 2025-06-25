package privacy

import (
	"fmt"

	"github.com/threagile/threagile/pkg/types"
)

type InsecureDataStorageRule struct{}

func NewInsecureDataStorageRule() *InsecureDataStorageRule {
	return &InsecureDataStorageRule{}
}

func (r InsecureDataStorageRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "insecure-data-storage",
		Title:                      "Insecure Data Storage",
		Description:                "Insecure Data Storage risk can result into privacy issues when data is stored in persistent storage-based technical assets with no encryption at rest enabled and they connect with external entities or assets without sharing a trust zone (boundary).",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check NIST Privacy Controls Framework",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Adopt encryption at rest techniques.",
		Mitigation:                 "Secure personal data by applying strong encryption using established industry algorithms for data whether it's stationary or in transit.",
		Check:                      "Are recommendations from OWASP Insecure Data Storage addressed? https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Rule identifies risks where: (1) Data is stored in technical assets without encryption, (2) These assets communicate with external entities across trust boundaries.",
		RiskAssessment:             "The risk rating depends on sufficient encryption of data stored.",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*InsecureDataStorageRule) SupportedTags() []string {
	return []string{"insecure-data-storage"}
}

func (r *InsecureDataStorageRule) GenerateRisks(model *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, t := range model.TechnicalAssets {
		if !t.IsPersistentStorageIDS() || t.Encryption != types.NoneEncryption {
			continue
		}
		for _, l := range t.CommunicationLinks {
			linkTarget := model.TechnicalAssets[l.TargetId]
			if linkTarget.Type == types.ExternalEntity &&
				!model.IsSameTrustBoundary(t.Id, linkTarget.Id) {
				// unencryptedAssets = append(unencryptedAssets, t.Id)
				riskyComponents := fmt.Sprintf("Unencrypted, externally-facing persistent storage: %s to ext. entity %s", t.Id, linkTarget.Id)
				risks = append(risks, r.createRisk(t, riskyComponents))
			}
		}
	}
	return risks, nil
}

func (r *InsecureDataStorageRule) createRisk(technicalAsset *types.TechnicalAsset, titleMod string) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.VeryLikely, types.HighImpact),
		ExploitationLikelihood:       types.VeryLikely,
		ExploitationImpact:           types.HighImpact,
		Title:                        "<b>Insecure Data Storage </b> risk at <b>" + technicalAsset.Title + "</b>: " + titleMod,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
