package types

type Risk struct {
	CategoryId                      string                     `yaml:"category" json:"category"`       // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	RiskStatus                      RiskStatus                 `yaml:"risk_status" json:"risk_status"` // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	Severity                        RiskSeverity               `yaml:"severity" json:"severity"`
	ExploitationLikelihood          RiskExploitationLikelihood `yaml:"exploitation_likelihood" json:"exploitation_likelihood"`
	ExploitationImpact              RiskExploitationImpact     `yaml:"exploitation_impact" json:"exploitation_impact"`
	Title                           string                     `yaml:"title" json:"title"`
	SyntheticId                     string                     `yaml:"synthetic_id" json:"synthetic_id"`
	MostRelevantDataAssetId         string                     `yaml:"most_relevant_data_asset" json:"most_relevant_data_asset"`
	MostRelevantTechnicalAssetId    string                     `yaml:"most_relevant_technical_asset" json:"most_relevant_technical_asset"`
	MostRelevantTrustBoundaryId     string                     `yaml:"most_relevant_trust_boundary" json:"most_relevant_trust_boundary"`
	MostRelevantSharedRuntimeId     string                     `yaml:"most_relevant_shared_runtime" json:"most_relevant_shared_runtime"`
	MostRelevantCommunicationLinkId string                     `yaml:"most_relevant_communication_link" json:"most_relevant_communication_link"`
	DataBreachProbability           DataBreachProbability      `yaml:"data_breach_probability" json:"data_breach_probability"`
	DataBreachTechnicalAssetIDs     []string                   `yaml:"data_breach_technical_assets" json:"data_breach_technical_assets"`
	// TODO: refactor all "Id" here to "ID"?
}

func (what Risk) GetRiskTracking(model *ParsedModel) RiskTracking { // TODO: Unify function naming regarding Get etc.
	var result RiskTracking
	if riskTracking, ok := model.RiskTracking[what.SyntheticId]; ok {
		result = riskTracking
	}
	return result
}

func (what Risk) GetRiskTrackingStatusDefaultingUnchecked(model *ParsedModel) RiskStatus {
	if riskTracking, ok := model.RiskTracking[what.SyntheticId]; ok {
		return riskTracking.Status
	}
	return Unchecked
}

func (what Risk) IsRiskTracked(model *ParsedModel) bool {
	if _, ok := model.RiskTracking[what.SyntheticId]; ok {
		return true
	}
	return false
}
