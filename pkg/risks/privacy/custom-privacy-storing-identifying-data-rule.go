package privacy

import (
	"fmt"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

type StoringIdentifyingDataRule struct{}

func NewStoringIdentifyingDataRule() *StoringIdentifyingDataRule {
	return &StoringIdentifyingDataRule{}
}

func (r StoringIdentifyingDataRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "storing-identifying-data",
		Title:                      "Storing Identifying Data",
		Description:                "When a technical asset is storing personal information (PI) such as direct identifiers (e.g. SSN) or a set of quasi-identifiers above some threshold (3) then Storing Identifying Data risk is present except if they are required for the functionality e.g. authentication purposes. Quasi-identifiers are combinations of data that, while not unique on their own, can collectively identify a data subject.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check NIST Privacy Controls Framework",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Implement data minimization principles.",
		Mitigation:                 "Enforce data minimization. Store only essential personal data and anonymize, de-identify or pseudonymize data in storage.",
		Check:                      "Are Identifiability concerns as described from LINDDUN threat trees (I.2) addressed?",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "The rule identifies risks where: (1) Technical assets store Direct Identifiers (DI), (2) Technical assets store a combination of Quasi-Identifiers (QI) that exceed a threshold (default is 3). These risks are flagged unless the data is essential for the functionality (e.g., authentication purposes)",
		RiskAssessment:             "The risk rating depends on sufficient encryption of inbound data.",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*StoringIdentifyingDataRule) SupportedTags() []string {
	return []string{"storing-identifying-data"}
}

var PersistStgTech = map[string]bool{
	"file-server":             true,
	"local-file-system":       true,
	"identity-store-database": true,
	"data-lake":               true,
	"hsm":                     true,
	"block-storage":           true,
	"database":                true}

var OrgPersistStgTags = map[string]bool{
	"s3-bucket": true,
	"hsm":       true,
	"kms-aws":   true}

func isPersistentStorage(t *types.TechnicalAsset) bool {

	var flag bool = false
	if t.Type == types.Datastore {
		return true
	}
	for _, technology := range t.Technologies {
		_, isPersistentStgTech := PersistStgTech[technology.String()]
		if isPersistentStgTech {
			return true
		}
	}

	for _, tag := range t.Tags {
		_, isOrgPersistStgTags := OrgPersistStgTags[tag]
		if isOrgPersistStgTags {
			return true
		}
	}
	return flag
}

var threshQuasiIDSID = 3

func (r *StoringIdentifyingDataRule) GenerateRisks(model *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	if model.Deidentified {
		return risks, nil
	}

	for _, t := range model.TechnicalAssets {
		if !isPersistentStorage(t) {
			continue
		}
		storedDI := types.GetDISet(t.DataAssetsStored, model.DataAssets)
		storedQDI := types.GetQuasiIDs(t.DataAssetsStored, model.DataAssets)
		var message string
		message = ""
		if (len(storedDI) > 0) && (len(storedQDI) >= threshQuasiID) {
			message = fmt.Sprintf("Stored - Direct Identifier(s): %s, Quasi Direct Identifier(s): %s", strings.Join(storedDI, ", "), strings.Join(storedQDI, ","))
		} else if len(storedDI) > 0 {
			message = fmt.Sprintf("Stored - Direct Identifier(s): %s", strings.Join(storedDI, ", "))
		} else if len(storedQDI) >= threshQuasiID {
			message = fmt.Sprintf("Stored - Quasi Direct Identifier(s): %s", strings.Join(storedQDI, ", "))
		}
		if len(message) > 0 {
			risks = append(risks, r.createRisk(t, message))
		}
	}

	return risks, nil
}

func (r *StoringIdentifyingDataRule) createRisk(technicalAsset *types.TechnicalAsset, titleMod string) *types.Risk {

	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.VeryLikely, types.HighImpact),
		ExploitationLikelihood:       types.VeryLikely,
		ExploitationImpact:           types.HighImpact,
		Title:                        "<b>Storing Indentifying Data</b> risk at <b>" + technicalAsset.Title + "</b>: " + titleMod,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
