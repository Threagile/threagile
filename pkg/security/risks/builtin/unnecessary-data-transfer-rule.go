package builtin

import (
	"sort"

	"github.com/threagile/threagile/pkg/security/types"
)

type UnnecessaryDataTransferRule struct{}

func NewUnnecessaryDataTransferRule() *UnnecessaryDataTransferRule {
	return &UnnecessaryDataTransferRule{}
}

func (*UnnecessaryDataTransferRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unnecessary-data-transfer",
		Title: "Unnecessary Data Transfer",
		Description: "When a technical asset sends or receives data assets, which it neither processes or stores this is " +
			"an indicator for unnecessarily transferred data (or for an incomplete model). When the unnecessarily " +
			"transferred data assets are sensitive, this poses an unnecessary risk of an increased attack surface.",
		Impact:     "If this risk is unmitigated, attackers might be able to target unnecessarily transferred data.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Attack Surface Reduction",
		Mitigation: "Try to avoid sending or receiving sensitive data assets which are not required (i.e. neither " +
			"processed) by the involved technical asset.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets sending or receiving sensitive data assets which are neither processed nor " +
			"stored by the technical asset are flagged with this risk. The risk rating (low or medium) depends on the " +
			"confidentiality, integrity, and availability rating of the technical asset. Monitoring data is exempted from this risk.",
		RiskAssessment: "The risk assessment is depending on the confidentiality and integrity rating of the transferred data asset " +
			"either " + types.LowSeverity.String() + " or " + types.MediumSeverity.String() + ".",
		FalsePositives: "Technical assets missing the model entries of either processing or storing the mentioned data assets " +
			"can be considered as false positives (incomplete models) after individual review. These should then be addressed by " +
			"completing the model so that all necessary data assets are processed by the technical asset involved.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func (*UnnecessaryDataTransferRule) SupportedTags() []string {
	return []string{}
}

func (r *UnnecessaryDataTransferRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		// outgoing data flows
		for _, outgoingDataFlow := range technicalAsset.CommunicationLinks {
			targetAsset := input.TechnicalAssets[outgoingDataFlow.TargetId]
			if targetAsset.Technologies.GetAttribute(types.IsUnnecessaryDataTolerated) {
				continue
			}
			risks = r.checkRisksAgainstTechnicalAsset(input, risks, technicalAsset, outgoingDataFlow, false)
		}
		// incoming data flows
		commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		sort.Sort(types.ByTechnicalCommunicationLinkIdSort(commLinks))
		for _, incomingDataFlow := range commLinks {
			targetAsset := input.TechnicalAssets[incomingDataFlow.SourceId]
			if targetAsset.Technologies.GetAttribute(types.IsUnnecessaryDataTolerated) {
				continue
			}
			risks = r.checkRisksAgainstTechnicalAsset(input, risks, technicalAsset, incomingDataFlow, true)
		}
	}
	return risks, nil
}

func (r *UnnecessaryDataTransferRule) checkRisksAgainstTechnicalAsset(input *types.Model, risks []*types.Risk, technicalAsset *types.TechnicalAsset, dataFlow *types.CommunicationLink, inverseDirection bool) []*types.Risk {
	for _, transferredDataAssetId := range dataFlow.DataAssetsSent {
		if !technicalAsset.ProcessesOrStoresDataAsset(transferredDataAssetId) {
			transferredDataAsset := input.DataAssets[transferredDataAssetId]
			//fmt.Print("--->>> Checking "+technicalAsset.ID+": "+transferredDataAsset.ID+" sent via "+dataFlow.ID+"\n")
			if transferredDataAsset.Confidentiality >= types.Confidential || transferredDataAsset.Integrity >= types.Critical {
				commPartnerId := dataFlow.TargetId
				if inverseDirection {
					commPartnerId = dataFlow.SourceId
				}
				commPartnerAsset := input.TechnicalAssets[commPartnerId]
				risk := r.createRisk(technicalAsset, transferredDataAsset, commPartnerAsset)
				if isNewRisk(risks, risk) {
					risks = append(risks, risk)
				}
			}
		}
	}
	for _, transferredDataAssetId := range dataFlow.DataAssetsReceived {
		if !technicalAsset.ProcessesOrStoresDataAsset(transferredDataAssetId) {
			transferredDataAsset := input.DataAssets[transferredDataAssetId]
			//fmt.Print("--->>> Checking "+technicalAsset.ID+": "+transferredDataAsset.ID+" received via "+dataFlow.ID+"\n")
			if transferredDataAsset.Confidentiality >= types.Confidential || transferredDataAsset.Integrity >= types.Critical {
				commPartnerId := dataFlow.TargetId
				if inverseDirection {
					commPartnerId = dataFlow.SourceId
				}
				commPartnerAsset := input.TechnicalAssets[commPartnerId]
				risk := r.createRisk(technicalAsset, transferredDataAsset, commPartnerAsset)
				if isNewRisk(risks, risk) {
					risks = append(risks, risk)
				}
			}
		}
	}
	return risks
}

func isNewRisk(risks []*types.Risk, risk *types.Risk) bool {
	for _, check := range risks {
		if check.SyntheticId == risk.SyntheticId {
			return false
		}
	}
	return true
}

func (r *UnnecessaryDataTransferRule) createRisk(technicalAsset *types.TechnicalAsset, dataAssetTransferred *types.DataAsset, commPartnerAsset *types.TechnicalAsset) *types.Risk {
	moreRisky := dataAssetTransferred.Confidentiality == types.StrictlyConfidential || dataAssetTransferred.Integrity == types.MissionCritical

	impact := types.LowImpact
	if moreRisky {
		impact = types.MediumImpact
	}

	title := "<b>Unnecessary Data Transfer</b> of <b>" + dataAssetTransferred.Title + "</b> data at <b>" + technicalAsset.Title + "</b> " +
		"from/to <b>" + commPartnerAsset.Title + "</b>"
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		MostRelevantDataAssetId:      dataAssetTransferred.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + dataAssetTransferred.Id + "@" + technicalAsset.Id + "@" + commPartnerAsset.Id
	return risk
}
