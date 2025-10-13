package builtin

import (
	"slices"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

type MissingCloudHardeningRule struct{}

func NewMissingCloudHardeningRule() *MissingCloudHardeningRule {
	return &MissingCloudHardeningRule{}
}

func (*MissingCloudHardeningRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-cloud-hardening",
		Title: "Missing Cloud Hardening",
		Description: "Cloud components should be hardened according to the cloud vendor best practices. This affects their " +
			"configuration, auditing, and further areas.",
		Impact:     "If this risk is unmitigated, attackers might access cloud components in an unintended way.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Cloud Hardening",
		Mitigation: "Apply hardening of all cloud components and services, taking special care to follow the individual risk descriptions (which " +
			"depend on the cloud provider tags in the model). " +
			"<br><br>For <b>Amazon Web Services (AWS)</b>: Follow the <i>CIS Benchmark for Amazon Web Services</i> (see also the automated checks of cloud audit tools like <i>\"PacBot\", \"CloudSploit\", \"CloudMapper\", \"ScoutSuite\", or \"Prowler AWS CIS Benchmark Tool\"</i>). " +
			"<br>For EC2 and other servers running Amazon Linux, follow the <i>CIS Benchmark for Amazon Linux</i> and switch to IMDSv2. " +
			"<br>For S3 buckets follow the <i>Security Best Practices for Amazon S3</i> at <a href=\"https://docs.aws.amazon.com/AmazonS3/latest/dev/security-best-practices.html\">https://docs.aws.amazon.com/AmazonS3/latest/dev/security-best-practices.html</a> to avoid accidental leakage. " +
			"<br>Also take a look at some of these tools: <a href=\"https://github.com/toniblyx/my-arsenal-of-aws-security-tools\">https://github.com/toniblyx/my-arsenal-of-aws-security-tools</a> " +
			"<br><br>For <b>Microsoft Azure</b>: Follow the <i>CIS Benchmark for Microsoft Azure</i> (see also the automated checks of cloud audit tools like <i>\"CloudSploit\" or \"ScoutSuite\"</i>)." +
			"<br><br>For <b>Google Cloud Platform</b>: Follow the <i>CIS Benchmark for Google Cloud Computing Platform</i> (see also the automated checks of cloud audit tools like <i>\"CloudSploit\" or \"ScoutSuite\"</i>). " +
			"<br><br>For <b>Oracle Cloud Platform</b>: Follow the hardening best practices (see also the automated checks of cloud audit tools like <i>\"CloudSploit\"</i>).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Operations,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope cloud components (either residing in cloud trust boundaries or more specifically tagged with cloud provider types).",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Cloud components not running parts of the target architecture can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

var specificSubTagsAWS = []string{"aws:vpc", "aws:ec2", "aws:s3", "aws:ebs", "aws:apigateway", "aws:lambda", "aws:dynamodb", "aws:rds", "aws:sqs", "aws:iam"}
var providers = []string{"AWS", "Azure", "GCP", "OCP"}

func (*MissingCloudHardeningRule) SupportedTags() []string {
	res := []string{
		"aws",   // Amazon AWS
		"azure", // Microsoft Azure
		"gcp",   // Google Cloud Platform
		"ocp",   // Oracle Cloud Platform
	}
	res = append(res, specificSubTagsAWS...)
	return res
}

type CloudAssets struct {
	SharedRuntimeIDs map[string]struct{}
	TrustBoundaryIDs map[string]struct{}
	TechAssetIDs     map[string]struct{}
}

func (r *MissingCloudHardeningRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	cloudAssets := initCloudAssets([]string{"AWS", "Azure", "GCP", "OCP", "Unspecified"})
	techAssetIDsWithSubtagSpecificCloudRisks := make(map[string]struct{})

	risks := make([]*types.Risk, 0)
	addedFlags := map[string]*bool{
		"AWS":   new(bool),
		"Azure": new(bool),
		"GCP":   new(bool),
		"OCP":   new(bool),
	}

	r.collectCloudAssets(input, cloudAssets, techAssetIDsWithSubtagSpecificCloudRisks)
	r.deduplicateUnspecifiedAssets(cloudAssets)

	risks = append(risks, r.generateSharedRuntimeRisks(input, cloudAssets, addedFlags)...)
	risks = append(risks, r.generateTrustBoundaryRisks(input, cloudAssets, addedFlags)...)
	risks = append(risks, r.addFallbackAssetRisks(input, cloudAssets, addedFlags)...)
	risks = append(risks, r.addSubtagSpecificRisks(input, techAssetIDsWithSubtagSpecificCloudRisks)...)

	return risks, nil
}

func (r *MissingCloudHardeningRule) collectCloudAssets(input *types.Model, cloudAssets map[string]*CloudAssets, techAssetIDsWithSubtagSpecificCloudRisks map[string]struct{}) {
	for _, trustBoundary := range input.TrustBoundaries {
		if !trustBoundary.IsTaggedWithAny(r.SupportedTags()...) && !trustBoundary.Type.IsWithinCloud() {
			continue
		}
		r.addTrustBoundaryAccordingToBaseTag(trustBoundary, cloudAssets)
		for _, techAssetID := range input.RecursivelyAllTechnicalAssetIDsInside(trustBoundary) {
			tA := input.TechnicalAssets[techAssetID]
			switch {
			case tA.IsTaggedWithAny(r.SupportedTags()...):
				addAccordingToBaseTag(tA, tA.Tags, techAssetIDsWithSubtagSpecificCloudRisks, cloudAssets)
			case trustBoundary.IsTaggedWithAny(r.SupportedTags()...):
				addAccordingToBaseTag(tA, trustBoundary.Tags, techAssetIDsWithSubtagSpecificCloudRisks, cloudAssets)
			default:
				cloudAssets["Unspecified"].TechAssetIDs[techAssetID] = struct{}{}
			}
		}
	}

	for _, tA := range input.TechnicalAssetsTaggedWithAny(r.SupportedTags()...) {
		addAccordingToBaseTag(tA, tA.Tags, techAssetIDsWithSubtagSpecificCloudRisks, cloudAssets)
	}

	for _, tB := range input.TrustBoundariesTaggedWithAny(r.SupportedTags()...) {
		for _, techAssetID := range input.RecursivelyAllTechnicalAssetIDsInside(tB) {
			tA := input.TechnicalAssets[techAssetID]
			tagsToUse := tB.Tags
			if tA.IsTaggedWithAny(r.SupportedTags()...) {
				tagsToUse = tA.Tags
			}
			addAccordingToBaseTag(tA, tagsToUse, techAssetIDsWithSubtagSpecificCloudRisks, cloudAssets)
		}
	}

	for _, sR := range input.SharedRuntimes {
		r.addSharedRuntimeAccordingToBaseTag(sR, cloudAssets)
		for _, techAssetID := range sR.TechnicalAssetsRunning {
			tA := input.TechnicalAssets[techAssetID]
			addAccordingToBaseTag(tA, sR.Tags, techAssetIDsWithSubtagSpecificCloudRisks, cloudAssets)
		}
	}
}

func (r *MissingCloudHardeningRule) deduplicateUnspecifiedAssets(cloudAssets map[string]*CloudAssets) {
	providers := []string{"AWS", "Azure", "GCP", "OCP"}
	for _, provider := range providers {
		for id := range cloudAssets[provider].SharedRuntimeIDs {
			delete(cloudAssets["Unspecified"].SharedRuntimeIDs, id)
		}
		for id := range cloudAssets[provider].TrustBoundaryIDs {
			delete(cloudAssets["Unspecified"].TrustBoundaryIDs, id)
		}
		for id := range cloudAssets[provider].TechAssetIDs {
			delete(cloudAssets["Unspecified"].TechAssetIDs, id)
		}
	}
}

func (r *MissingCloudHardeningRule) generateSharedRuntimeRisks(input *types.Model, cloudAssets map[string]*CloudAssets, addedFlags map[string]*bool) []*types.Risk {
	risks := []*types.Risk{}
	for _, cfg := range r.cloudConfigs(addedFlags) {
		for id := range cloudAssets[cfg.Provider].SharedRuntimeIDs {
			risks = append(risks, r.createRiskForSharedRuntime(input, input.SharedRuntimes[id], cfg.Provider, cfg.Benchmark))
			*cfg.AddedFlag = true
		}
	}
	for id := range cloudAssets["Unspecified"].SharedRuntimeIDs {
		risks = append(risks, r.createRiskForSharedRuntime(input, input.SharedRuntimes[id], "", ""))
	}
	return risks
}

func (r *MissingCloudHardeningRule) generateTrustBoundaryRisks(input *types.Model, cloudAssets map[string]*CloudAssets, addedFlags map[string]*bool) []*types.Risk {
	risks := []*types.Risk{}
	for _, cfg := range r.cloudConfigs(addedFlags) {
		for id := range cloudAssets[cfg.Provider].TrustBoundaryIDs {
			risks = append(risks, r.createRiskForTrustBoundary(input, input.TrustBoundaries[id], cfg.Provider, cfg.Benchmark))
			*cfg.AddedFlag = true
		}
	}
	for id := range cloudAssets["Unspecified"].TrustBoundaryIDs {
		risks = append(risks, r.createRiskForTrustBoundary(input, input.TrustBoundaries[id], "", ""))
	}
	return risks
}

func (r *MissingCloudHardeningRule) addFallbackAssetRisks(input *types.Model, cloudAssets map[string]*CloudAssets, addedFlags map[string]*bool) []*types.Risk {
	risks := []*types.Risk{}
	for _, cfg := range r.cloudConfigs(addedFlags) {
		if !*cfg.AddedFlag {
			mostRelevant := findMostSensitiveTechnicalAsset(input, cloudAssets[cfg.Provider].TechAssetIDs)
			if mostRelevant != nil {
				risks = append(risks, r.createRiskForTechnicalAsset(input, mostRelevant, cfg.Provider, cfg.Benchmark))
			}
		}
	}
	return risks
}

func (r *MissingCloudHardeningRule) addSubtagSpecificRisks(input *types.Model, ids map[string]struct{}) []*types.Risk {
	risks := []*types.Risk{}
	for id := range ids {
		tA := input.TechnicalAssets[id]
		if isTechnicalAssetTaggedWithAnyTraversingUp(input, tA, "aws:ec2") {
			risks = append(risks, r.createRiskForTechnicalAsset(input, tA, "EC2", "CIS Benchmark for Amazon Linux"))
		}
		if isTechnicalAssetTaggedWithAnyTraversingUp(input, tA, "aws:s3") {
			risks = append(risks, r.createRiskForTechnicalAsset(input, tA, "S3", "Security Best Practices for AWS S3"))
		}
		// TODO: add more subtag-specific risks
	}
	return risks
}

func (r *MissingCloudHardeningRule) cloudConfigs(added map[string]*bool) []struct {
	Provider  string
	Benchmark string
	AddedFlag *bool
} {
	return []struct {
		Provider  string
		Benchmark string
		AddedFlag *bool
	}{
		{"AWS", "CIS Benchmark for AWS", added["AWS"]},
		{"Azure", "CIS Benchmark for Microsoft Azure", added["Azure"]},
		{"GCP", "CIS Benchmark for Google Cloud Computing Platform", added["GCP"]},
		{"OCP", "Vendor Best Practices for Oracle Cloud Platform", added["OCP"]},
	}
}

func initCloudAssets(providers []string) map[string]*CloudAssets {
	assets := make(map[string]*CloudAssets, len(providers))
	for _, provider := range providers {
		assets[provider] = &CloudAssets{
			SharedRuntimeIDs: make(map[string]struct{}),
			TrustBoundaryIDs: make(map[string]struct{}),
			TechAssetIDs:     make(map[string]struct{}),
		}
	}
	return assets
}

func isTechnicalAssetTaggedWithAnyTraversingUp(model *types.Model, ta *types.TechnicalAsset, tags ...string) bool {
	if containsCaseInsensitiveAny(ta.Tags, tags...) {
		return true
	}

	if tbID := model.GetTechnicalAssetTrustBoundaryId(ta); tbID != "" {
		if isTrustedBoundaryTaggedWithAnyTraversingUp(model, model.TrustBoundaries[tbID], tags...) {
			return true
		}
	}

	for _, sr := range model.SharedRuntimes {
		if sr.IsTaggedWithAny(tags...) && contains(sr.TechnicalAssetsRunning, ta.Id) {
			return true
		}
	}

	return false
}

func isTrustedBoundaryTaggedWithAnyTraversingUp(model *types.Model, tb *types.TrustBoundary, tags ...string) bool {
	if tb.IsTaggedWithAny(tags...) {
		return true
	}
	parentTb := model.FindParentTrustBoundary(tb)
	if parentTb != nil && isTrustedBoundaryTaggedWithAnyTraversingUp(model, parentTb, tags...) {
		return true
	}
	return false
}

func (r *MissingCloudHardeningRule) addTrustBoundaryAccordingToBaseTag(
	trustBoundary *types.TrustBoundary,
	cloudAssets map[string]*CloudAssets,
) {
	if trustBoundary.IsTaggedWithAny(r.SupportedTags()...) {
		added := false
		for _, provider := range providers {
			if isTaggedWithBaseTag(trustBoundary.Tags, strings.ToLower(provider)) {
				cloudAssets[provider].TrustBoundaryIDs[trustBoundary.Id] = struct{}{}
				added = true
			}
		}
		if !added {
			cloudAssets["Unspecified"].TrustBoundaryIDs[trustBoundary.Id] = struct{}{}
		}
	} else {
		cloudAssets["Unspecified"].TrustBoundaryIDs[trustBoundary.Id] = struct{}{}
	}
}

func (r *MissingCloudHardeningRule) addSharedRuntimeAccordingToBaseTag(
	sharedRuntime *types.SharedRuntime,
	cloudAssets map[string]*CloudAssets,) {
	if sharedRuntime.IsTaggedWithAny(r.SupportedTags()...) {
		for _, provider := range providers {
			if isTaggedWithBaseTag(sharedRuntime.Tags, strings.ToLower(provider)) {
				cloudAssets[provider].SharedRuntimeIDs[sharedRuntime.Id] = struct{}{}
			}
		}
	} else {
		cloudAssets["Unspecified"].SharedRuntimeIDs[sharedRuntime.Id] = struct{}{}
	}
}

func addAccordingToBaseTag(
	techAsset *types.TechnicalAsset,
	tags []string,
	techAssetIDsWithTagSpecificCloudRisks map[string]struct{},
	cloudAssets map[string]*CloudAssets,
) {
	if techAsset.IsTaggedWithAny(specificSubTagsAWS...) {
		techAssetIDsWithTagSpecificCloudRisks[techAsset.Id] = struct{}{}
	}

	for _, provider := range providers {
		if isTaggedWithBaseTag(tags, strings.ToLower(provider)) {
			cloudAssets[provider].TechAssetIDs[techAsset.Id] = struct{}{}
		}
	}
}

func isTaggedWithBaseTag(tags []string, baseTag string) bool {
	normalizedBase := strings.ToLower(strings.TrimSpace(baseTag))
	prefix := normalizedBase + ":"

	for _, tag := range tags {
		normalizedTag := strings.ToLower(strings.TrimSpace(tag))
		if normalizedTag == normalizedBase || strings.HasPrefix(normalizedTag, prefix) {
			return true
		}
	}

	return false
}

func findMostSensitiveTechnicalAsset(input *types.Model, techAssets map[string]struct{}) *types.TechnicalAsset {
	var candidates []*types.TechnicalAsset
	for id := range techAssets {
		candidates = append(candidates, input.TechnicalAssets[id])
	}

	if len(candidates) == 0 {
		return nil
	}

	return slices.MaxFunc(candidates, func(a, b *types.TechnicalAsset) int {
		return int(a.HighestSensitivityScore() - b.HighestSensitivityScore())
	})
}

func (r *MissingCloudHardeningRule) createCloudHardeningRisk(id, title, prefix, details string, confidentiality types.Confidentiality, integrity types.Criticality, availability types.Criticality, relatedAssets []string) *types.Risk {
	suffix := ""
	if len(prefix) > 0 {
		suffix = "@" + strings.ToLower(prefix)
		prefix = " (" + prefix + ")"
	}

	fullTitle := "<b>Missing Cloud Hardening" + prefix + "</b> risk at <b>" + title + "</b>"
	if len(details) > 0 {
		fullTitle += ": <u>" + details + "</u>"
	}

	impact := types.MediumImpact
	if confidentiality >= types.Confidential || integrity >= types.Critical || availability >= types.Critical {
		impact = types.HighImpact
	}
	if confidentiality == types.StrictlyConfidential || integrity == types.MissionCritical || availability == types.MissionCritical {
		impact = types.VeryHighImpact
	}

	risk := &types.Risk{
		CategoryId:                  r.Category().ID,
		Severity:                    types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:      types.Unlikely,
		ExploitationImpact:          impact,
		Title:                       fullTitle,
		DataBreachProbability:       types.Probable,
		DataBreachTechnicalAssetIDs: relatedAssets,
		SyntheticId:                 r.Category().ID + "@" + id + suffix,
	}
	return risk
}

func (r *MissingCloudHardeningRule) createRiskForSharedRuntime(
	input *types.Model, sharedRuntime *types.SharedRuntime, prefix, details string) *types.Risk {
	return r.createCloudHardeningRisk(
		sharedRuntime.Id,
		sharedRuntime.Title,
		prefix,
		details,
		input.FindSharedRuntimeHighestConfidentiality(sharedRuntime),
		input.FindSharedRuntimeHighestIntegrity(sharedRuntime),
		input.FindSharedRuntimeHighestAvailability(sharedRuntime),
		sharedRuntime.TechnicalAssetsRunning,
	)
}

func (r *MissingCloudHardeningRule) createRiskForTrustBoundary(
	input *types.Model, trustBoundary *types.TrustBoundary, prefix, details string) *types.Risk {
	return r.createCloudHardeningRisk(
		trustBoundary.Id,
		trustBoundary.Title,
		prefix,
		details,
		input.FindTrustBoundaryHighestConfidentiality(trustBoundary),
		input.FindTrustBoundaryHighestIntegrity(trustBoundary),
		input.FindTrustBoundaryHighestAvailability(trustBoundary),
		input.RecursivelyAllTechnicalAssetIDsInside(trustBoundary),
	)
}

func (r *MissingCloudHardeningRule) createRiskForTechnicalAsset(
	input *types.Model, technicalAsset *types.TechnicalAsset, prefix, details string) *types.Risk {
	return r.createCloudHardeningRisk(
		technicalAsset.Id,
		technicalAsset.Title,
		prefix,
		details,
		input.HighestProcessedConfidentiality(technicalAsset),
		input.HighestProcessedIntegrity(technicalAsset),
		input.HighestProcessedAvailability(technicalAsset),
		[]string{technicalAsset.Id},
	)
}
