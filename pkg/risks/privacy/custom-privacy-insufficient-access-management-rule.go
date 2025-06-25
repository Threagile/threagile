package privacy

import (
	"github.com/threagile/threagile/pkg/types"
)

type InsufficientAccessManagementRule struct{}

func NewInsufficientAccessManagementRule() *InsufficientAccessManagementRule {
	return &InsufficientAccessManagementRule{}
}

func (*InsufficientAccessManagementRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:                         "insufficient-access-management",
		Title:                      "Insufficient Access Management",
		Description:                "Insufficient Access Management risk is present causing privacy loss if no authentication or authorizaion checks are applied for communication links over which Personal Information (PI) is received.",
		Impact:                     "Impact depends on previous knowledge.",
		ASVS:                       "Privacy Rule - Check NIST Privacy Controls Framework",
		CheatSheet:                 "OWASP Cheat Sheet Unavailable",
		Action:                     "Apply access management controls.",
		Mitigation:                 "Establish and enforce rigorous access controls to prevent unauthorized individuals from accessing sensitive data. This requires authenticating users securely, applying access permissions based on their roles, and validating their rights before granting access to sensitive information.",
		Check:                      "Are recommendations from OWASP Insecure Data Storage addressed? Are recommendations from OWASP Insecure Data Storage addressed? https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Rule identifies risks where: (1) Personal data (PI) is transferred over communication links. (2) The source technical asset lacks proper authentication or authorization mechanisms.",
		RiskAssessment:             "The risk rating depends on sufficient sufficient access control mechanisms of inbound access request.",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*InsufficientAccessManagementRule) SupportedTags() []string {
	return []string{"insufficient-access-management"}
}

var ReqAuthenticationCheckOnly = map[string]bool{
	"web-server":     true,
	"search-engine":  true,
	"reverse-proxy":  true,
	"load-balancer":  true,
	"event-listener": true,
	"cli":            true,
	"gateway":        true,
	"iot-device":     true,
	"message-queue":  true,
	"waf":            true,
	"ids":            true,
	"ips":            true,
}

var ReqBothAuthenAndAuthorChecks = map[string]bool{
	"client-system":            true,
	"desktop":                  true,
	"mobile-app":               true,
	"devops-client":            true,
	"web-application":          true,
	"application-server":       true,
	"database":                 true,
	"file-server":              true,
	"local-file-system":        true,
	"erp":                      true,
	"cms":                      true,
	"web-service-rest":         true,
	"web-service-soap":         true,
	"ejb":                      true,
	"search-index":             true,
	"service-registry":         true,
	"build-pipeline":           true,
	"sourcecode-repository":    true,
	"artifact-registry":        true,
	"code-inspection-platform": true,
	"monitoring":               true,
	"ldap-server":              true,
	"container-platform":       true,
	"identity-provider":        true,
	"identity-store-ldap":      true,
	"identity-store-database":  true,
	"data-lake":                true,
	"report-engine":            true,
	"ai":                       true,
	"mail-server":              true,
	"vault":                    true,
	"hsm":                      true,
	"block-storage":            true,
	"library":                  true}

func requiresAuthenticationCheckOnly(t *types.TechnicalAsset) bool {
	_, ok := ReqAuthenticationCheckOnly[t.Technologies.String()]
	return ok
}

func requireAuthorizationCheck(t *types.TechnicalAsset) bool {
	yes := false
	if t.Type == types.Datastore {
		yes = true
	} else {
		_, yes = ReqBothAuthenAndAuthorChecks[t.Technologies.String()]
	}
	return yes
}

type targetRecdDA struct {
	link                   types.CommunicationLink
	dataAssetsRecdByTarget []string
}

func getLinksTargetPerspective(model *types.Model) map[string][]targetRecdDA {
	targetLinks := make(map[string][]targetRecdDA)
	for _, t := range model.TechnicalAssets {
		for _, c := range t.CommunicationLinks {
			if len(c.DataAssetsSent) > 0 {
				var recdDA targetRecdDA
				recdDA.link = *c
				recdDA.dataAssetsRecdByTarget = c.DataAssetsSent
				_, ok := targetLinks[c.TargetId]
				if !ok {
					targetLinks[c.TargetId] = []targetRecdDA{recdDA}
				} else {
					targetLinks[c.TargetId] = append(targetLinks[c.TargetId], recdDA)
				}
			}

			if len(c.DataAssetsReceived) > 0 {
				var sourceRecdDA targetRecdDA
				sourceRecdDA.link = *c
				sourceRecdDA.dataAssetsRecdByTarget = c.DataAssetsReceived
				_, ok2 := targetLinks[c.SourceId]
				if !ok2 {
					targetLinks[c.SourceId] = []targetRecdDA{sourceRecdDA}
				} else {
					targetLinks[c.SourceId] = append(targetLinks[c.SourceId], sourceRecdDA)
				}
			}
		}
	}

	return targetLinks
}

var threshQuasiID = 5

func (r *InsufficientAccessManagementRule) GenerateRisks(model *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)

	targetLinks := getLinksTargetPerspective(model)
	for _, ta := range model.TechnicalAssets {
		listRecdDA := targetLinks[ta.Id]
		for _, c := range listRecdDA {
			if types.HasPI(c.dataAssetsRecdByTarget, model.DataAssets) {
				if requiresAuthenticationCheckOnly(model.TechnicalAssets[c.link.SourceId]) {
					if c.link.Authentication == types.NoneAuthentication {
						risks = append(risks, r.createRisk(model.TechnicalAssets[c.link.SourceId], c.link.TargetId))
					}
				} else if requireAuthorizationCheck(model.TechnicalAssets[c.link.SourceId]) {
					if c.link.Authentication == types.NoneAuthentication || c.link.Authorization == types.NoneAuthorization {
						risks = append(risks, r.createRisk(model.TechnicalAssets[c.link.SourceId], c.link.TargetId))
					}
				}
			}
		}
	}
	return risks, nil
}

func (r *InsufficientAccessManagementRule) createRisk(technicalAsset *types.TechnicalAsset, titleMod string) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.VeryLikely, types.HighImpact),
		ExploitationLikelihood:       types.VeryLikely,
		ExploitationImpact:           types.HighImpact,
		Title:                        "<b>Insufficient Access Management</b> risk at <b> target: " + titleMod + "</b> with source: " + technicalAsset.Title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
