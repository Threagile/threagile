package missing_cloud_hardening

import (
	"github.com/threagile/threagile/model"
	"sort"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-cloud-hardening",
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
		Function:       model.Operations,
		STRIDE:         model.Tampering,
		DetectionLogic: "In-scope cloud components (either residing in cloud trust boundaries or more specifically tagged with cloud provider types).",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed and stored.",
		FalsePositives: "Cloud components not running parts of the target architecture can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

var specificSubtagsAWS = []string{"aws:vpc", "aws:ec2", "aws:s3", "aws:ebs", "aws:apigateway", "aws:lambda", "aws:dynamodb", "aws:rds", "aws:sqs", "aws:iam"}

func SupportedTags() []string {
	res := []string{
		"aws",   // Amazon AWS
		"azure", // Microsoft Azure
		"gcp",   // Google Cloud Platform
		"ocp",   // Oracle Cloud Platform
	}
	res = append(res, specificSubtagsAWS...)
	return res
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)

	sharedRuntimesWithUnspecificCloudRisks := make(map[string]bool, 0)
	trustBoundariesWithUnspecificCloudRisks := make(map[string]bool, 0)
	techAssetsWithUnspecificCloudRisks := make(map[string]bool, 0)

	sharedRuntimeIDsAWS := make(map[string]bool, 0)
	trustBoundaryIDsAWS := make(map[string]bool, 0)
	techAssetIDsAWS := make(map[string]bool, 0)

	sharedRuntimeIDsAzure := make(map[string]bool, 0)
	trustBoundaryIDsAzure := make(map[string]bool, 0)
	techAssetIDsAzure := make(map[string]bool, 0)

	sharedRuntimeIDsGCP := make(map[string]bool, 0)
	trustBoundaryIDsGCP := make(map[string]bool, 0)
	techAssetIDsGCP := make(map[string]bool, 0)

	sharedRuntimeIDsOCP := make(map[string]bool, 0)
	trustBoundaryIDsOCP := make(map[string]bool, 0)
	techAssetIDsOCP := make(map[string]bool, 0)

	techAssetIDsWithSubtagSpecificCloudRisks := make(map[string]bool, 0)

	for _, trustBoundary := range model.ParsedModelRoot.TrustBoundaries {
		taggedOuterTB := trustBoundary.IsTaggedWithAny(SupportedTags()...) // false = generic cloud risks only // true = cloud-individual risks
		if taggedOuterTB || trustBoundary.Type.IsWithinCloud() {
			addTrustBoundaryAccordingToBasetag(trustBoundary, trustBoundariesWithUnspecificCloudRisks,
				trustBoundaryIDsAWS, trustBoundaryIDsAzure, trustBoundaryIDsGCP, trustBoundaryIDsOCP)
			for _, techAssetID := range trustBoundary.RecursivelyAllTechnicalAssetIDsInside() {
				added := false
				tA := model.ParsedModelRoot.TechnicalAssets[techAssetID]
				if tA.IsTaggedWithAny(SupportedTags()...) {
					addAccordingToBasetag(tA, tA.Tags,
						techAssetIDsWithSubtagSpecificCloudRisks,
						techAssetIDsAWS, techAssetIDsAzure, techAssetIDsGCP, techAssetIDsOCP)
					added = true
				} else if taggedOuterTB {
					addAccordingToBasetag(tA, trustBoundary.Tags,
						techAssetIDsWithSubtagSpecificCloudRisks,
						techAssetIDsAWS, techAssetIDsAzure, techAssetIDsGCP, techAssetIDsOCP)
					added = true
				}
				if !added {
					techAssetsWithUnspecificCloudRisks[techAssetID] = true
				}
			}
		}
	}

	// now loop over all technical assets, trust boundaries, and shared runtimes model-wide by tag
	for _, tA := range model.TechnicalAssetsTaggedWithAny(SupportedTags()...) {
		addAccordingToBasetag(tA, tA.Tags,
			techAssetIDsWithSubtagSpecificCloudRisks,
			techAssetIDsAWS, techAssetIDsAzure, techAssetIDsGCP, techAssetIDsOCP)
	}
	for _, tB := range model.TrustBoundariesTaggedWithAny(SupportedTags()...) {
		for _, candidateID := range tB.RecursivelyAllTechnicalAssetIDsInside() {
			tA := model.ParsedModelRoot.TechnicalAssets[candidateID]
			if tA.IsTaggedWithAny(SupportedTags()...) {
				addAccordingToBasetag(tA, tA.Tags,
					techAssetIDsWithSubtagSpecificCloudRisks,
					techAssetIDsAWS, techAssetIDsAzure, techAssetIDsGCP, techAssetIDsOCP)
			} else {
				addAccordingToBasetag(tA, tB.Tags,
					techAssetIDsWithSubtagSpecificCloudRisks,
					techAssetIDsAWS, techAssetIDsAzure, techAssetIDsGCP, techAssetIDsOCP)
			}
		}
	}
	for _, sR := range model.SharedRuntimesTaggedWithAny(SupportedTags()...) {
		addSharedRuntimeAccordingToBasetag(sR, sharedRuntimesWithUnspecificCloudRisks,
			sharedRuntimeIDsAWS, sharedRuntimeIDsAzure, sharedRuntimeIDsGCP, sharedRuntimeIDsOCP)
		for _, candidateID := range sR.TechnicalAssetsRunning {
			tA := model.ParsedModelRoot.TechnicalAssets[candidateID]
			addAccordingToBasetag(tA, sR.Tags,
				techAssetIDsWithSubtagSpecificCloudRisks,
				techAssetIDsAWS, techAssetIDsAzure, techAssetIDsGCP, techAssetIDsOCP)
		}
	}

	// remove from sharedRuntimesWithUnspecificCloudRisks all specific tagged assets
	for id := range sharedRuntimeIDsAWS {
		delete(sharedRuntimesWithUnspecificCloudRisks, id)
	}
	for id := range sharedRuntimeIDsAzure {
		delete(sharedRuntimesWithUnspecificCloudRisks, id)
	}
	for id := range sharedRuntimeIDsGCP {
		delete(sharedRuntimesWithUnspecificCloudRisks, id)
	}
	for id := range sharedRuntimeIDsOCP {
		delete(sharedRuntimesWithUnspecificCloudRisks, id)
	}

	// remove from trustBoundariesWithUnspecificCloudRisks all specific tagged assets
	for id := range trustBoundaryIDsAWS {
		delete(trustBoundariesWithUnspecificCloudRisks, id)
	}
	for id := range trustBoundaryIDsAzure {
		delete(trustBoundariesWithUnspecificCloudRisks, id)
	}
	for id := range trustBoundaryIDsGCP {
		delete(trustBoundariesWithUnspecificCloudRisks, id)
	}
	for id := range trustBoundaryIDsOCP {
		delete(trustBoundariesWithUnspecificCloudRisks, id)
	}

	// remove from techAssetsWithUnspecificCloudRisks all specific tagged assets
	for techAssetID := range techAssetIDsWithSubtagSpecificCloudRisks {
		delete(techAssetsWithUnspecificCloudRisks, techAssetID)
	}
	for techAssetID := range techAssetIDsAWS {
		delete(techAssetsWithUnspecificCloudRisks, techAssetID)
	}
	for techAssetID := range techAssetIDsAzure {
		delete(techAssetsWithUnspecificCloudRisks, techAssetID)
	}
	for techAssetID := range techAssetIDsGCP {
		delete(techAssetsWithUnspecificCloudRisks, techAssetID)
	}
	for techAssetID := range techAssetIDsOCP {
		delete(techAssetsWithUnspecificCloudRisks, techAssetID)
	}

	// NOW ACTUALLY CREATE THE RISKS
	addedAWS, addedAzure, addedGCP, addedOCP := false, false, false, false

	// first try to add shared runtimes...
	for id := range sharedRuntimeIDsAWS {
		risks = append(risks, createRiskForSharedRuntime(model.ParsedModelRoot.SharedRuntimes[id], "AWS", "CIS Benchmark for AWS"))
		addedAWS = true
	}
	for id := range sharedRuntimeIDsAzure {
		risks = append(risks, createRiskForSharedRuntime(model.ParsedModelRoot.SharedRuntimes[id], "Azure", "CIS Benchmark for Microsoft Azure"))
		addedAzure = true
	}
	for id := range sharedRuntimeIDsGCP {
		risks = append(risks, createRiskForSharedRuntime(model.ParsedModelRoot.SharedRuntimes[id], "GCP", "CIS Benchmark for Google Cloud Computing Platform"))
		addedGCP = true
	}
	for id := range sharedRuntimeIDsOCP {
		risks = append(risks, createRiskForSharedRuntime(model.ParsedModelRoot.SharedRuntimes[id], "OCP", "Vendor Best Practices for Oracle Cloud Platform"))
		addedOCP = true
	}
	for id := range sharedRuntimesWithUnspecificCloudRisks {
		risks = append(risks, createRiskForSharedRuntime(model.ParsedModelRoot.SharedRuntimes[id], "", ""))
	}

	// ... followed by trust boundaries for the generic risks
	for id := range trustBoundaryIDsAWS {
		risks = append(risks, createRiskForTrustBoundary(model.ParsedModelRoot.TrustBoundaries[id], "AWS", "CIS Benchmark for AWS"))
		addedAWS = true
	}
	for id := range trustBoundaryIDsAzure {
		risks = append(risks, createRiskForTrustBoundary(model.ParsedModelRoot.TrustBoundaries[id], "Azure", "CIS Benchmark for Microsoft Azure"))
		addedAzure = true
	}
	for id := range trustBoundaryIDsGCP {
		risks = append(risks, createRiskForTrustBoundary(model.ParsedModelRoot.TrustBoundaries[id], "GCP", "CIS Benchmark for Google Cloud Computing Platform"))
		addedGCP = true
	}
	for id := range trustBoundaryIDsOCP {
		risks = append(risks, createRiskForTrustBoundary(model.ParsedModelRoot.TrustBoundaries[id], "OCP", "Vendor Best Practices for Oracle Cloud Platform"))
		addedOCP = true
	}
	for id := range trustBoundariesWithUnspecificCloudRisks {
		risks = append(risks, createRiskForTrustBoundary(model.ParsedModelRoot.TrustBoundaries[id], "", ""))
	}

	// just use the most sensitive asset as an example - to only create one general "AWS cloud hardening" risk, not many
	if !addedAWS {
		mostRelevantAsset := findMostSensitiveTechnicalAsset(techAssetIDsAWS)
		if !mostRelevantAsset.IsZero() {
			risks = append(risks, createRiskForTechnicalAsset(mostRelevantAsset, "AWS", "CIS Benchmark for AWS"))
			addedAWS = true
		}
	}
	// just use the most sensitive asset as an example - to only create one general "Azure cloud hardening" risk, not many
	if !addedAzure {
		mostRelevantAsset := findMostSensitiveTechnicalAsset(techAssetIDsAzure)
		if !mostRelevantAsset.IsZero() {
			risks = append(risks, createRiskForTechnicalAsset(mostRelevantAsset, "Azure", "CIS Benchmark for Microsoft Azure"))
			addedAzure = true
		}
	}
	// just use the most sensitive asset as an example - to only create one general "GCP cloud hardening" risk, not many
	if !addedGCP {
		mostRelevantAsset := findMostSensitiveTechnicalAsset(techAssetIDsGCP)
		if !mostRelevantAsset.IsZero() {
			risks = append(risks, createRiskForTechnicalAsset(mostRelevantAsset, "GCP", "CIS Benchmark for Google Cloud Computing Platform"))
			addedGCP = true
		}
	}
	// just use the most sensitive asset as an example - to only create one general "GCP cloud hardening" risk, not many
	if !addedOCP {
		mostRelevantAsset := findMostSensitiveTechnicalAsset(techAssetIDsOCP)
		if !mostRelevantAsset.IsZero() {
			risks = append(risks, createRiskForTechnicalAsset(mostRelevantAsset, "OCP", "Vendor Best Practices for Oracle Cloud Platform"))
			addedOCP = true
		}
	}

	// now also add all tech asset specific tag-specific risks, as they are specific to the asset anyway (therefore don't set added to true here)
	for id := range techAssetIDsWithSubtagSpecificCloudRisks {
		tA := model.ParsedModelRoot.TechnicalAssets[id]
		if tA.IsTaggedWithAnyTraversingUp("aws:ec2") {
			risks = append(risks, createRiskForTechnicalAsset(tA, "EC2", "CIS Benchmark for Amazon Linux"))
		}
		if tA.IsTaggedWithAnyTraversingUp("aws:s3") {
			risks = append(risks, createRiskForTechnicalAsset(tA, "S3", "Security Best Practices for AWS S3"))
		}
		// TODO add more tag-specific risks like also for aws:lambda etc. here
	}

	return risks
}

func addTrustBoundaryAccordingToBasetag(trustBoundary model.TrustBoundary,
	trustBoundariesWithUnspecificCloudRisks map[string]bool,
	trustBoundaryIDsAWS map[string]bool,
	trustBoundaryIDsAzure map[string]bool,
	trustBoundaryIDsGCP map[string]bool,
	trustBoundaryIDsOCP map[string]bool) {
	if trustBoundary.IsTaggedWithAny(SupportedTags()...) {
		if trustBoundary.IsTaggedWithBaseTag("aws") {
			trustBoundaryIDsAWS[trustBoundary.Id] = true
		}
		if trustBoundary.IsTaggedWithBaseTag("azure") {
			trustBoundaryIDsAzure[trustBoundary.Id] = true
		}
		if trustBoundary.IsTaggedWithBaseTag("gcp") {
			trustBoundaryIDsGCP[trustBoundary.Id] = true
		}
		if trustBoundary.IsTaggedWithBaseTag("ocp") {
			trustBoundaryIDsOCP[trustBoundary.Id] = true
		}
	} else {
		trustBoundariesWithUnspecificCloudRisks[trustBoundary.Id] = true
	}
}

func addSharedRuntimeAccordingToBasetag(sharedRuntime model.SharedRuntime,
	sharedRuntimesWithUnspecificCloudRisks map[string]bool,
	sharedRuntimeIDsAWS map[string]bool,
	sharedRuntimeIDsAzure map[string]bool,
	sharedRuntimeIDsGCP map[string]bool,
	sharedRuntimeIDsOCP map[string]bool) {
	if sharedRuntime.IsTaggedWithAny(SupportedTags()...) {
		if sharedRuntime.IsTaggedWithBaseTag("aws") {
			sharedRuntimeIDsAWS[sharedRuntime.Id] = true
		}
		if sharedRuntime.IsTaggedWithBaseTag("azure") {
			sharedRuntimeIDsAzure[sharedRuntime.Id] = true
		}
		if sharedRuntime.IsTaggedWithBaseTag("gcp") {
			sharedRuntimeIDsGCP[sharedRuntime.Id] = true
		}
		if sharedRuntime.IsTaggedWithBaseTag("ocp") {
			sharedRuntimeIDsOCP[sharedRuntime.Id] = true
		}
	} else {
		sharedRuntimesWithUnspecificCloudRisks[sharedRuntime.Id] = true
	}
}

func addAccordingToBasetag(techAsset model.TechnicalAsset, tags []string,
	techAssetIDsWithTagSpecificCloudRisks map[string]bool,
	techAssetIDsAWS map[string]bool,
	techAssetIDsAzure map[string]bool,
	techAssetIDsGCP map[string]bool,
	techAssetIDsOCP map[string]bool) {
	if techAsset.IsTaggedWithAny(specificSubtagsAWS...) {
		techAssetIDsWithTagSpecificCloudRisks[techAsset.Id] = true
	}
	if model.IsTaggedWithBaseTag(tags, "aws") {
		techAssetIDsAWS[techAsset.Id] = true
	}
	if model.IsTaggedWithBaseTag(tags, "azure") {
		techAssetIDsAzure[techAsset.Id] = true
	}
	if model.IsTaggedWithBaseTag(tags, "gcp") {
		techAssetIDsGCP[techAsset.Id] = true
	}
	if model.IsTaggedWithBaseTag(tags, "ocp") {
		techAssetIDsOCP[techAsset.Id] = true
	}
}

func findMostSensitiveTechnicalAsset(techAssets map[string]bool) model.TechnicalAsset {
	var mostRelevantAsset model.TechnicalAsset
	keys := make([]string, 0, len(techAssets))
	for k := range techAssets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, id := range keys {
		tA := model.ParsedModelRoot.TechnicalAssets[id]
		if mostRelevantAsset.IsZero() || tA.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
			mostRelevantAsset = tA
		}
	}
	return mostRelevantAsset
}

func createRiskForSharedRuntime(sharedRuntime model.SharedRuntime, prefix, details string) model.Risk {
	if len(prefix) > 0 {
		prefix = " (" + prefix + ")"
	}
	title := "<b>Missing Cloud Hardening" + prefix + "</b> risk at <b>" + sharedRuntime.Title + "</b>"
	if len(details) > 0 {
		title += ": <u>" + details + "</u>"
	}
	impact := model.MediumImpact
	if sharedRuntime.HighestConfidentiality() >= model.Confidential ||
		sharedRuntime.HighestIntegrity() >= model.Critical ||
		sharedRuntime.HighestAvailability() >= model.Critical {
		impact = model.HighImpact
	}
	if sharedRuntime.HighestConfidentiality() == model.StrictlyConfidential ||
		sharedRuntime.HighestIntegrity() == model.MissionCritical ||
		sharedRuntime.HighestAvailability() == model.MissionCritical {
		impact = model.VeryHighImpact
	}
	// create risk
	risk := model.Risk{
		Category:                    Category(),
		Severity:                    model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:      model.Unlikely,
		ExploitationImpact:          impact,
		Title:                       title,
		MostRelevantSharedRuntimeId: sharedRuntime.Id,
		DataBreachProbability:       model.Probable,
		DataBreachTechnicalAssetIDs: sharedRuntime.TechnicalAssetsRunning,
	}
	risk.SyntheticId = risk.Category.Id + "@" + sharedRuntime.Id
	return risk
}

func createRiskForTrustBoundary(trustBoundary model.TrustBoundary, prefix, details string) model.Risk {
	if len(prefix) > 0 {
		prefix = " (" + prefix + ")"
	}
	title := "<b>Missing Cloud Hardening" + prefix + "</b> risk at <b>" + trustBoundary.Title + "</b>"
	if len(details) > 0 {
		title += ": <u>" + details + "</u>"
	}
	impact := model.MediumImpact
	if trustBoundary.HighestConfidentiality() >= model.Confidential ||
		trustBoundary.HighestIntegrity() >= model.Critical ||
		trustBoundary.HighestAvailability() >= model.Critical {
		impact = model.HighImpact
	}
	if trustBoundary.HighestConfidentiality() == model.StrictlyConfidential ||
		trustBoundary.HighestIntegrity() == model.MissionCritical ||
		trustBoundary.HighestAvailability() == model.MissionCritical {
		impact = model.VeryHighImpact
	}
	// create risk
	risk := model.Risk{
		Category:                    Category(),
		Severity:                    model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:      model.Unlikely,
		ExploitationImpact:          impact,
		Title:                       title,
		MostRelevantTrustBoundaryId: trustBoundary.Id,
		DataBreachProbability:       model.Probable,
		DataBreachTechnicalAssetIDs: trustBoundary.RecursivelyAllTechnicalAssetIDsInside(),
	}
	risk.SyntheticId = risk.Category.Id + "@" + trustBoundary.Id
	return risk
}

func createRiskForTechnicalAsset(technicalAsset model.TechnicalAsset, prefix, details string) model.Risk {
	if len(prefix) > 0 {
		prefix = " (" + prefix + ")"
	}
	title := "<b>Missing Cloud Hardening" + prefix + "</b> risk at <b>" + technicalAsset.Title + "</b>"
	if len(details) > 0 {
		title += ": <u>" + details + "</u>"
	}
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() >= model.Confidential ||
		technicalAsset.HighestIntegrity() >= model.Critical ||
		technicalAsset.HighestAvailability() >= model.Critical {
		impact = model.HighImpact
	}
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.VeryHighImpact
	}
	// create risk
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
