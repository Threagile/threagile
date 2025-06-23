package privacy

import (
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

type ReceivingIdentifyingDataRule struct{}

func NewReceivingIdentifyingDataRule() *ReceivingIdentifyingDataRule {
	return &ReceivingIdentifyingDataRule{}
}

func (r ReceivingIdentifyingDataRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "receiving-identifying-data",
		Title:                      "Receiving Identifying Data",
		Description:                "When a technical asset is receiving personal information (PI) such as direct identifiers (e.g. SSN) or a set of quasi-identifiers above some threshold (3) then Receiving Identifying Data risk is present except if they are required for the functionality e.g. for authentication purposes. Quasi-identifiers are combinations of data that, while not unique on their own, can collectively identify a data subject.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check NIST Privacy Controls Framework",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Implement data minimization principles.",
		Mitigation:                 "Collect only essential personal data in requests. Examine if users or assets need to send identified data for providing functionality. If not stop collecting it. Remove direct identifiers or replace them with tokens/pseudonyms early. Analyze if the quasi-identifiers are re-used across different assets or if they are present in some public dataset which could identify back to the data subject. Broaden or remove attributes that, in combination, could identify users (quasi-identifiers).",
		Check:                      "Are Identifiability concerns as described from LINDDUN threat trees (I.1, I.2.1) addressed?",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "The rule identifies risks where: (1) Non-authenticating systems or non-network management systems receive Direct Identifiers (DI), (2) These systems receive a combination of Quasi-Identifiers (QI) that exceed a threshold (default is 3).",
		RiskAssessment:             "The risk rating depends on sufficient encryption of inbound data.",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*ReceivingIdentifyingDataRule) SupportedTags() []string {
	return []string{"receiving-identifying-data"}
}

var AuthSystemsSet = map[string]bool{
	"ldap-server":         true,
	"identity-provider":   true,
	"identity-store-ldap": true,
	"vault":               true}

var NWMgrSet = map[string]bool{
	"reverse-proxy": true,
	"load-balancer": true,
	"gateway":       true,
	"service-mesh":  true,
	"waf":           true,
	"ids":           true,
	"ips":           true}

func isNonAuthenticationSystem(t *types.TechnicalAsset) bool {
	f := true
	if t.Id == "cyberark" {
		f = false
	} else {
		for _, technologiesI := range t.Technologies {
			_, ok := AuthSystemsSet[technologiesI.String()]
			if ok {
				f = false
				break
			}
		}
	}
	return f
}

func isNWMgrSet(t *types.TechnicalAsset) bool {
	f := false
	for _, technologiesI := range t.Technologies {
		_, ok := NWMgrSet[technologiesI.String()]
		if ok {
			f = ok
			break
		}
	}
	return f
}

type targetRecdDARID struct {
	link                   types.CommunicationLink
	dataAssetsRecdByTarget []string
}

func getLinksTargetPerspectiveRID(model *types.Model) map[string][]targetRecdDARID {
	targetLinks := make(map[string][]targetRecdDARID)
	for _, t := range model.TechnicalAssets {
		for _, c := range t.CommunicationLinks {
			if len(c.DataAssetsSent) > 0 {
				var recdDA targetRecdDARID
				recdDA.link = *c
				recdDA.dataAssetsRecdByTarget = c.DataAssetsSent
				_, ok := targetLinks[c.TargetId]
				if !ok {
					targetLinks[c.TargetId] = []targetRecdDARID{recdDA}
				} else {
					targetLinks[c.TargetId] = append(targetLinks[c.TargetId], recdDA)
				}
			}

			if len(c.DataAssetsReceived) > 0 {
				var sourceRecdDA targetRecdDARID
				sourceRecdDA.link = *c
				sourceRecdDA.dataAssetsRecdByTarget = c.DataAssetsReceived
				_, ok2 := targetLinks[c.SourceId]
				if !ok2 {
					targetLinks[c.SourceId] = []targetRecdDARID{sourceRecdDA}
				} else {
					targetLinks[c.SourceId] = append(targetLinks[c.SourceId], sourceRecdDA)
				}
			}
		}
	}
	return targetLinks
}

var threshQuasiIDRID = 3

func (r *ReceivingIdentifyingDataRule) GenerateRisks(model *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	if model.Deidentified {
		return risks, nil
	}

	targetLinks := getLinksTargetPerspectiveRID(model)
	for pseudoTargetAssetID := range targetLinks {
		pseudoTargetAsset := model.TechnicalAssets[pseudoTargetAssetID]
		if isNonAuthenticationSystem(pseudoTargetAsset) && (!isNWMgrSet(pseudoTargetAsset)) {
			for _, tgtRecdDA := range targetLinks[pseudoTargetAssetID] {
				if len(tgtRecdDA.dataAssetsRecdByTarget) > 0 {
					DISet := types.GetDISet(tgtRecdDA.dataAssetsRecdByTarget, model.DataAssets)
					if len(DISet) > 0 {
						risks = append(risks, r.createRisk(pseudoTargetAsset, strings.Join(DISet, ", ")))
					}
					QISet := types.GetQuasiIDs(tgtRecdDA.dataAssetsRecdByTarget, model.DataAssets)
					if len(QISet) >= threshQuasiIDRID {
						risks = append(risks, r.createRisk(pseudoTargetAsset, strings.Join(QISet, ", ")))
					}
				}
			}
		}
	}
	return risks, nil
}

func (r *ReceivingIdentifyingDataRule) createRisk(technicalAsset *types.TechnicalAsset, titleMod string) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.VeryLikely, types.HighImpact),
		ExploitationLikelihood:       types.VeryLikely,
		ExploitationImpact:           types.HighImpact,
		Title:                        "<b>Receiving Indentifying Data</b> risk at <b>" + technicalAsset.Title + "</b>: " + titleMod,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
