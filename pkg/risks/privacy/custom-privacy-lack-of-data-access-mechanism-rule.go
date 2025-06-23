package privacy

import (
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

type LackOfDataAccessMechanismRule struct{}

func NewLackOfDataAccessMechanismRule() *LackOfDataAccessMechanismRule {
	return &LackOfDataAccessMechanismRule{}
}

func (*LackOfDataAccessMechanismRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "lack-of-data-access-mechanism",
		Title:                      "Lack of Data Access Mechanism",
		Description:                "Lack of Data Access Mechanism privacy risk is present if the user is not able to access their personal information from the system due to lack of such a mechanism.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check LINDDUN threat category Unawareness and Unintervenability (U.2.2)",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Ensure mechanisms exist for data subjects to be able to access data directly or indirectly.",
		Mitigation:                 "Provide data subjects with the means to access their personal data that is being collected, processed, or stored.",
		Check:                      "Are Unawareness and Unintervenability concerns as described from LINDDUN threat trees (U.2.2) addressed?",
		Function:                   types.Architecture,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Rule identifies risks when the system does not provide a mechanism for users to access their personal data (PIUserAccessMechanism == false). It flags all personal data (PI) assets as being at risk due to the lack of access mechanisms.",
		RiskAssessment:             types.MediumSeverity.String(), // (?)
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*LackOfDataAccessMechanismRule) SupportedTags() []string {
	return []string{"lack-of-data-access-mechanism"}
}

func (r *LackOfDataAccessMechanismRule) GenerateRisks(model *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)

	if model.PIUserAccessMechanism {
		return risks, nil
	}
	PIID := make([]string, 0)
	DAsInTheModel := model.DataAssets
	for _, da := range DAsInTheModel {
		if da.PINameType.IsPI() {
			PIID = append(PIID, da.Id)
		}
	}
	if len(PIID) != 0 {
		sort.Strings(PIID)
		for _, piID := range PIID {
			risks = append(risks, r.createRisk(piID))
		}
	}

	return risks, nil
}

func (r *LackOfDataAccessMechanismRule) createRisk(piID string) *types.Risk {
	risk := &types.Risk{
		CategoryId:              r.Category().ID,
		Severity:                types.CalculateSeverity(types.VeryLikely, types.MediumImpact),
		ExploitationLikelihood:  types.VeryLikely,
		ExploitationImpact:      types.MediumImpact,
		Title:                   "<b>Lack of data access control mechanism</b> risk at <b> PI: " + piID + "</b>.",
		MostRelevantDataAssetId: piID,
		DataBreachProbability:   types.Possible,
	}
	risk.SyntheticId = risk.CategoryId + "@" + piID
	return risk
}
