package privacy

import (
	"github.com/threagile/threagile/pkg/types"
)

type ImproperPIManagementRule struct{}

func NewImproperPIManagementRule() *ImproperPIManagementRule {
	return &ImproperPIManagementRule{}
}

func (*ImproperPIManagementRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "improper-pi-management",
		Title:                      "Improper PI Management",
		Description:                "Improper PI Management risk arises when the model-owning organization does not have proper data lifecycle management in place, which could lead to privacy risks or data management issues.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check NIST Privacy Controls Framework",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Establish and implement proper data lifecycle management principles.",
		Mitigation:                 "Establish and execute proper data lifecycle management. The management of the data lifecycle is a continuous responsibility that needs to be consistently performed as long as the system is under design, in development, and in operation.", //Rephrase what LINDDUN suggests
		Check:                      "Are Data Disclosure concerns as described from LINDDUN threat trees (Nc.2) addressed?",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Rule identifies risks when the organization does not have proper data lifecycle management (HasDataLifeCycleMgmt == false). It flags all personal data (PI) assets as being improperly managed.",
		RiskAssessment:             types.MediumSeverity.String(),
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*ImproperPIManagementRule) SupportedTags() []string {
	return []string{"improper-pi-management"}
}

func (r *ImproperPIManagementRule) GenerateRisks(model *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	setDA := make([]string, 0) // set of data asset IDs

	if model.HasDataLifeCycleMgmt {
		return risks, nil
	}

	for _, da := range model.DataAssets {
		setDA = append(setDA, da.Id)
	}

	setPI := model.GetPI(setDA)

	for _, pi := range setPI {
		risks = append(risks, r.createRisk(model.DataAssets[pi], pi))
	}

	return risks, nil

}

func (r *ImproperPIManagementRule) createRisk(dataAsset *types.DataAsset, titleMod string) *types.Risk {
	risk := &types.Risk{
		CategoryId:              r.Category().ID,
		Severity:                types.RiskSeverity(types.MediumImpact),
		ExploitationLikelihood:  types.Unlikely,
		ExploitationImpact:      types.MediumImpact,
		Title:                   "<b>Improper PI Management</b> risk at target : " + dataAsset.Title + "</b> with PI: " + titleMod,
		MostRelevantDataAssetId: dataAsset.Id,
		DataBreachProbability:   types.Possible,
	}
	risk.SyntheticId = risk.CategoryId + "@" + dataAsset.Id
	return risk
}
