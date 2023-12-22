package unnecessary_data_transfer

import (
	"sort"

	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/types"
)

func Rule() model.CustomRiskRule {
	return model.CustomRiskRule{
		Category:      Category,
		SupportedTags: SupportedTags,
		GenerateRisks: GenerateRisks,
	}
}

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unnecessary-data-transfer",
		Title: "Unnecessary Data Transfer",
		Description: "When a technical asset sends or receives data assets, which it neither processes or stores this is " +
			"an indicator for unnecessarily transferred data (or for an incomplete model). When the unnecessarily " +
			"transferred data assets are sensitive, this poses an unnecessary risk of an increased attack surface.",
		Impact:     "If this risk is unmitigated, attackers might be able to target unnecessarily transferred data.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Attack Surface Reduction",
		Mitigation: "Try to avoid sending or receiving sensitive data assets which are not required (i.e. neither " +
			"processed or stored) by the involved technical asset.",
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
			"completing the model so that all necessary data assets are processed and/or stored by the technical asset involved.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks(input *model.ParsedModel) []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		// outgoing data flows
		for _, outgoingDataFlow := range technicalAsset.CommunicationLinks {
			targetAsset := input.TechnicalAssets[outgoingDataFlow.TargetId]
			if targetAsset.Technology.IsUnnecessaryDataTolerated() {
				continue
			}
			risks = checkRisksAgainstTechnicalAsset(input, risks, technicalAsset, outgoingDataFlow, false)
		}
		// incoming data flows
		commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		sort.Sort(model.ByTechnicalCommunicationLinkIdSort(commLinks))
		for _, incomingDataFlow := range commLinks {
			targetAsset := input.TechnicalAssets[incomingDataFlow.SourceId]
			if targetAsset.Technology.IsUnnecessaryDataTolerated() {
				continue
			}
			risks = checkRisksAgainstTechnicalAsset(input, risks, technicalAsset, incomingDataFlow, true)
		}
	}
	return risks
}

func checkRisksAgainstTechnicalAsset(input *model.ParsedModel, risks []model.Risk, technicalAsset model.TechnicalAsset,
	dataFlow model.CommunicationLink, inverseDirection bool) []model.Risk {
	for _, transferredDataAssetId := range dataFlow.DataAssetsSent {
		if !technicalAsset.ProcessesOrStoresDataAsset(transferredDataAssetId) {
			transferredDataAsset := input.DataAssets[transferredDataAssetId]
			//fmt.Print("--->>> Checking "+technicalAsset.Id+": "+transferredDataAsset.Id+" sent via "+dataFlow.Id+"\n")
			if transferredDataAsset.Confidentiality >= types.Confidential || transferredDataAsset.Integrity >= types.Critical {
				commPartnerId := dataFlow.TargetId
				if inverseDirection {
					commPartnerId = dataFlow.SourceId
				}
				commPartnerAsset := input.TechnicalAssets[commPartnerId]
				risk := createRisk(technicalAsset, transferredDataAsset, commPartnerAsset)
				if isNewRisk(risks, risk) {
					risks = append(risks, risk)
				}
			}
		}
	}
	for _, transferredDataAssetId := range dataFlow.DataAssetsReceived {
		if !technicalAsset.ProcessesOrStoresDataAsset(transferredDataAssetId) {
			transferredDataAsset := input.DataAssets[transferredDataAssetId]
			//fmt.Print("--->>> Checking "+technicalAsset.Id+": "+transferredDataAsset.Id+" received via "+dataFlow.Id+"\n")
			if transferredDataAsset.Confidentiality >= types.Confidential || transferredDataAsset.Integrity >= types.Critical {
				commPartnerId := dataFlow.TargetId
				if inverseDirection {
					commPartnerId = dataFlow.SourceId
				}
				commPartnerAsset := input.TechnicalAssets[commPartnerId]
				risk := createRisk(technicalAsset, transferredDataAsset, commPartnerAsset)
				if isNewRisk(risks, risk) {
					risks = append(risks, risk)
				}
			}
		}
	}
	return risks
}

func isNewRisk(risks []model.Risk, risk model.Risk) bool {
	for _, check := range risks {
		if check.SyntheticId == risk.SyntheticId {
			return false
		}
	}
	return true
}

func createRisk(technicalAsset model.TechnicalAsset, dataAssetTransferred model.DataAsset, commPartnerAsset model.TechnicalAsset) model.Risk {
	moreRisky := dataAssetTransferred.Confidentiality == types.StrictlyConfidential || dataAssetTransferred.Integrity == types.MissionCritical

	impact := types.LowImpact
	if moreRisky {
		impact = types.MediumImpact
	}

	title := "<b>Unnecessary Data Transfer</b> of <b>" + dataAssetTransferred.Title + "</b> data at <b>" + technicalAsset.Title + "</b> " +
		"from/to <b>" + commPartnerAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		MostRelevantDataAssetId:      dataAssetTransferred.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataAssetTransferred.Id + "@" + technicalAsset.Id + "@" + commPartnerAsset.Id
	return risk
}
