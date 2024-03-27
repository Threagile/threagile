package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type SqlNoSqlInjectionRule struct{}

func NewSqlNoSqlInjectionRule() *SqlNoSqlInjectionRule {
	return &SqlNoSqlInjectionRule{}
}

func (*SqlNoSqlInjectionRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:    "sql-nosql-injection",
		Title: "SQL/NoSQL-Injection",
		Description: "When a database is accessed via database access protocols SQL/NoSQL-Injection risks might arise. " +
			"The risk rating depends on the sensitivity technical asset itself and of the data assets processed.",
		Impact:     "If this risk is unmitigated, attackers might be able to modify SQL/NoSQL queries to steal and modify data and eventually further escalate towards a deeper system penetration via code executions.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		Action:     "SQL/NoSQL-Injection Prevention",
		Mitigation: "Try to use parameter binding to be safe from injection vulnerabilities. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "Database accessed via typical database access protocols by in-scope clients.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data stored inside the database.",
		FalsePositives: "Database accesses by queries not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        89,
	}
}

func (*SqlNoSqlInjectionRule) SupportedTags() []string {
	return []string{}
}

func (r *SqlNoSqlInjectionRule) GenerateRisks(input *types.ParsedModel) []types.Risk {
	risks := make([]types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if input.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			if incomingFlow.Protocol.IsPotentialDatabaseAccessProtocol(true) && technicalAsset.Technologies.GetAttribute(types.IsVulnerableToQueryInjection) ||
				incomingFlow.Protocol.IsPotentialDatabaseAccessProtocol(false) {
				risks = append(risks, r.createRisk(input, technicalAsset, incomingFlow))
			}
		}
	}
	return risks
}

func (r *SqlNoSqlInjectionRule) createRisk(input *types.ParsedModel, technicalAsset types.TechnicalAsset, incomingFlow types.CommunicationLink) types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>SQL/NoSQL-Injection</b> risk at <b>" + caller.Title + "</b> against database <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := types.MediumImpact
	if technicalAsset.HighestProcessedConfidentiality(input) == types.StrictlyConfidential || technicalAsset.HighestProcessedIntegrity(input) == types.MissionCritical {
		impact = types.HighImpact
	}
	likelihood := types.VeryLikely
	if incomingFlow.Usage == types.DevOps {
		likelihood = types.Likely
	}
	risk := types.Risk{
		CategoryId:                      r.Category().Id,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
