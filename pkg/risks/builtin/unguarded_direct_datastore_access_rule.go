package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type UnguardedDirectDatastoreAccessRule struct{}

func NewUnguardedDirectDatastoreAccessRule() *UnguardedDirectDatastoreAccessRule {
	return &UnguardedDirectDatastoreAccessRule{}
}

func (*UnguardedDirectDatastoreAccessRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "unguarded-direct-datastore-access",
		Title:       "Unguarded Direct Datastore Access",
		Description: "Data stores accessed across trust boundaries must be guarded by some protecting service or application.",
		Impact:      "If this risk is unmitigated, attackers might be able to directly attack sensitive data stores without any protecting components in-between.",
		ASVS:        "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:      "Encapsulation of Datastore",
		Mitigation:  "Encapsulate the datastore access behind a guarding service or application.",
		Check:       "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:    types.Architecture,
		STRIDE:      types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets of type " + types.Datastore.String() + " (except " + types.IdentityStoreLDAP + " when accessed from " + types.IdentityProvider + " and " + types.FileServer + " when accessed via file transfer protocols) with confidentiality rating " +
			"of " + types.Confidential.String() + " (or higher) or with integrity rating of " + types.Critical.String() + " (or higher) " +
			"which have incoming data-flows from assets outside across a network trust-boundary. DevOps config and deployment access is excluded from this risk.", // TODO new rule "missing bastion host"?
		RiskAssessment: "The matching technical assets are at " + types.LowSeverity.String() + " risk. When either the " +
			"confidentiality rating is " + types.StrictlyConfidential.String() + " or the integrity rating " +
			"is " + types.MissionCritical.String() + ", the risk-rating is considered " + types.MediumSeverity.String() + ". " +
			"For assets with RAA values higher than 40 % the risk-rating increases.",
		FalsePositives:             "When the caller is considered fully trusted as if it was part of the datastore itself.",
		ModelFailurePossibleReason: false,
		CWE:                        501,
	}
}

func (*UnguardedDirectDatastoreAccessRule) SupportedTags() []string {
	return []string{}
}

// check for data stores that should not be accessed directly across trust boundaries

func (r *UnguardedDirectDatastoreAccessRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Type != types.Datastore {
			continue
		}
		for _, incomingAccess := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			sourceAsset := input.TechnicalAssets[incomingAccess.SourceId]
			if technicalAsset.Technologies.GetAttribute(types.IsIdentityStore) && sourceAsset.Technologies.GetAttribute(types.IdentityProvider) {
				continue
			}
			if technicalAsset.Confidentiality < types.Confidential && technicalAsset.Integrity < types.Critical {
				continue
			}
			if incomingAccess.Usage == types.DevOps {
				continue
			}
			if !isAcrossTrustBoundaryNetworkOnly(input, incomingAccess) || fileServerAccessViaFTP(technicalAsset, incomingAccess) ||
				isSharingSameParentTrustBoundary(input, technicalAsset, sourceAsset) {
				continue
			}

			highRisk := technicalAsset.Confidentiality == types.StrictlyConfidential ||
				technicalAsset.Integrity == types.MissionCritical
			risks = append(risks, r.createRisk(technicalAsset, incomingAccess,
				input.TechnicalAssets[incomingAccess.SourceId], highRisk))
		}
	}
	return risks, nil
}

func isSharingSameParentTrustBoundary(input *types.Model, left, right *types.TechnicalAsset) bool {
	tbIDLeft, tbIDRight := left.GetTrustBoundaryId(input), right.GetTrustBoundaryId(input)
	if len(tbIDLeft) == 0 && len(tbIDRight) > 0 {
		return false
	}
	if len(tbIDLeft) > 0 && len(tbIDRight) == 0 {
		return false
	}
	if len(tbIDLeft) == 0 && len(tbIDRight) == 0 {
		return true
	}
	if tbIDLeft == tbIDRight {
		return true
	}
	tbLeft, tbRight := input.TrustBoundaries[tbIDLeft], input.TrustBoundaries[tbIDRight]
	tbParentsLeft, tbParentsRight := input.AllParentTrustBoundaryIDs(tbLeft), input.AllParentTrustBoundaryIDs(tbRight)
	for _, parentLeft := range tbParentsLeft {
		for _, parentRight := range tbParentsRight {
			if parentLeft == parentRight {
				return true
			}
		}
	}
	return false
}

func fileServerAccessViaFTP(technicalAsset *types.TechnicalAsset, incomingAccess *types.CommunicationLink) bool {
	return technicalAsset.Technologies.GetAttribute(types.FileServer) &&
		(incomingAccess.Protocol == types.FTP || incomingAccess.Protocol == types.FTPS || incomingAccess.Protocol == types.SFTP)
}

func (r *UnguardedDirectDatastoreAccessRule) createRisk(dataStore *types.TechnicalAsset, dataFlow *types.CommunicationLink, clientOutsideTrustBoundary *types.TechnicalAsset, moreRisky bool) *types.Risk {
	impact := types.LowImpact
	if moreRisky || dataStore.RAA > 40 {
		impact = types.MediumImpact
	}
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(types.Likely, impact),
		ExploitationLikelihood: types.Likely,
		ExploitationImpact:     impact,
		Title: "<b>Unguarded Direct Datastore Access</b> of <b>" + dataStore.Title + "</b> by <b>" +
			clientOutsideTrustBoundary.Title + "</b> via <b>" + dataFlow.Title + "</b>",
		MostRelevantTechnicalAssetId:    dataStore.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{dataStore.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + dataFlow.Id + "@" + clientOutsideTrustBoundary.Id + "@" + dataStore.Id
	return risk
}
