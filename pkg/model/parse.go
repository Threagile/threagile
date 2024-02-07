package model

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
)

func ParseModel(modelInput *input.Model, builtinRiskRules map[string]risks.RiskRule, customRiskRules map[string]*CustomRisk) (*types.ParsedModel, error) {
	businessCriticality, err := types.ParseCriticality(modelInput.BusinessCriticality)
	if err != nil {
		return nil, fmt.Errorf("unknown 'business_criticality' value of application: %v", modelInput.BusinessCriticality)
	}

	reportDate := time.Now()
	if len(modelInput.Date) > 0 {
		var parseError error
		reportDate, parseError = time.Parse("2006-01-02", modelInput.Date)
		if parseError != nil {
			return nil, fmt.Errorf("unable to parse 'date' value of model file (expected format: '2006-01-02')")
		}
	}

	parsedModel := types.ParsedModel{
		ThreagileVersion:               modelInput.ThreagileVersion,
		Title:                          modelInput.Title,
		Author:                         modelInput.Author,
		Contributors:                   modelInput.Contributors,
		Date:                           types.Date{Time: reportDate},
		AppDescription:                 removePathElementsFromImageFiles(modelInput.AppDescription),
		BusinessOverview:               removePathElementsFromImageFiles(modelInput.BusinessOverview),
		TechnicalOverview:              removePathElementsFromImageFiles(modelInput.TechnicalOverview),
		BusinessCriticality:            businessCriticality,
		ManagementSummaryComment:       modelInput.ManagementSummaryComment,
		SecurityRequirements:           modelInput.SecurityRequirements,
		Questions:                      modelInput.Questions,
		AbuseCases:                     modelInput.AbuseCases,
		TagsAvailable:                  lowerCaseAndTrim(modelInput.TagsAvailable),
		DiagramTweakNodesep:            modelInput.DiagramTweakNodesep,
		DiagramTweakRanksep:            modelInput.DiagramTweakRanksep,
		DiagramTweakEdgeLayout:         modelInput.DiagramTweakEdgeLayout,
		DiagramTweakSuppressEdgeLabels: modelInput.DiagramTweakSuppressEdgeLabels,
		DiagramTweakLayoutLeftToRight:  modelInput.DiagramTweakLayoutLeftToRight,
		DiagramTweakInvisibleConnectionsBetweenAssets: modelInput.DiagramTweakInvisibleConnectionsBetweenAssets,
		DiagramTweakSameRankAssets:                    modelInput.DiagramTweakSameRankAssets,
	}

	parsedModel.CommunicationLinks = make(map[string]types.CommunicationLink)
	parsedModel.AllSupportedTags = make(map[string]bool)
	parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId = make(map[string][]types.CommunicationLink)
	parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId = make(map[string]types.TrustBoundary)
	parsedModel.GeneratedRisksByCategory = make(map[string][]types.Risk)
	parsedModel.GeneratedRisksBySyntheticId = make(map[string]types.Risk)

	if parsedModel.DiagramTweakNodesep == 0 {
		parsedModel.DiagramTweakNodesep = 2
	}
	if parsedModel.DiagramTweakRanksep == 0 {
		parsedModel.DiagramTweakRanksep = 2
	}

	// Data Assets ===============================================================================
	parsedModel.DataAssets = make(map[string]types.DataAsset)
	for title, asset := range modelInput.DataAssets {
		id := fmt.Sprintf("%v", asset.ID)

		usage, err := types.ParseUsage(asset.Usage)
		if err != nil {
			return nil, fmt.Errorf("unknown 'usage' value of data asset %q: %v", title, asset.Usage)
		}
		quantity, err := types.ParseQuantity(asset.Quantity)
		if err != nil {
			return nil, fmt.Errorf("unknown 'quantity' value of data asset %q: %v", title, asset.Quantity)
		}
		confidentiality, err := types.ParseConfidentiality(asset.Confidentiality)
		if err != nil {
			return nil, fmt.Errorf("unknown 'confidentiality' value of data asset %q: %v", title, asset.Confidentiality)
		}
		integrity, err := types.ParseCriticality(asset.Integrity)
		if err != nil {
			return nil, fmt.Errorf("unknown 'integrity' value of data asset %q: %v", title, asset.Integrity)
		}
		availability, err := types.ParseCriticality(asset.Availability)
		if err != nil {
			return nil, fmt.Errorf("unknown 'availability' value of data asset %q: %v", title, asset.Availability)
		}

		err = checkIdSyntax(id)
		if err != nil {
			return nil, err
		}
		if _, exists := parsedModel.DataAssets[id]; exists {
			return nil, fmt.Errorf("duplicate id used: %v", id)
		}
		tags, err := parsedModel.CheckTags(lowerCaseAndTrim(asset.Tags), "data asset '"+title+"'")
		if err != nil {
			return nil, err
		}
		parsedModel.DataAssets[id] = types.DataAsset{
			Id:                     id,
			Title:                  title,
			Usage:                  usage,
			Description:            withDefault(fmt.Sprintf("%v", asset.Description), title),
			Quantity:               quantity,
			Tags:                   tags,
			Origin:                 fmt.Sprintf("%v", asset.Origin),
			Owner:                  fmt.Sprintf("%v", asset.Owner),
			Confidentiality:        confidentiality,
			Integrity:              integrity,
			Availability:           availability,
			JustificationCiaRating: fmt.Sprintf("%v", asset.JustificationCiaRating),
		}
	}

	// Technical Assets ===============================================================================
	parsedModel.TechnicalAssets = make(map[string]types.TechnicalAsset)
	for title, asset := range modelInput.TechnicalAssets {
		id := fmt.Sprintf("%v", asset.ID)

		usage, err := types.ParseUsage(asset.Usage)
		if err != nil {
			return nil, fmt.Errorf("unknown 'usage' value of technical asset %q: %v", title, asset.Usage)
		}

		var dataAssetsStored = make([]string, 0)
		if asset.DataAssetsStored != nil {
			for _, parsedStoredAssets := range asset.DataAssetsStored {
				referencedAsset := fmt.Sprintf("%v", parsedStoredAssets)
				if contains(dataAssetsStored, referencedAsset) {
					continue
				}

				err := parsedModel.CheckDataAssetTargetExists(referencedAsset, fmt.Sprintf("technical asset %q", title))
				if err != nil {
					return nil, err
				}
				dataAssetsStored = append(dataAssetsStored, referencedAsset)
			}
		}

		var dataAssetsProcessed = dataAssetsStored
		if asset.DataAssetsProcessed != nil {
			for _, parsedProcessedAsset := range asset.DataAssetsProcessed {
				referencedAsset := fmt.Sprintf("%v", parsedProcessedAsset)
				if contains(dataAssetsProcessed, referencedAsset) {
					continue
				}

				err := parsedModel.CheckDataAssetTargetExists(referencedAsset, "technical asset '"+title+"'")
				if err != nil {
					return nil, err
				}
				dataAssetsProcessed = append(dataAssetsProcessed, referencedAsset)
			}
		}

		technicalAssetType, err := types.ParseTechnicalAssetType(asset.Type)
		if err != nil {
			return nil, fmt.Errorf("unknown 'type' value of technical asset %q: %v", title, asset.Type)
		}
		technicalAssetSize, err := types.ParseTechnicalAssetSize(asset.Size)
		if err != nil {
			return nil, fmt.Errorf("unknown 'size' value of technical asset %q: %v", title, asset.Size)
		}
		technicalAssetTechnology, err := types.ParseTechnicalAssetTechnology(asset.Technology)
		if err != nil {
			return nil, fmt.Errorf("unknown 'technology' value of technical asset %q: %v", title, asset.Technology)
		}
		encryption, err := types.ParseEncryptionStyle(asset.Encryption)
		if err != nil {
			return nil, fmt.Errorf("unknown 'encryption' value of technical asset %q: %v", title, asset.Encryption)
		}
		technicalAssetMachine, err := types.ParseTechnicalAssetMachine(asset.Machine)
		if err != nil {
			return nil, fmt.Errorf("unknown 'machine' value of technical asset %q: %v", title, asset.Machine)
		}
		confidentiality, err := types.ParseConfidentiality(asset.Confidentiality)
		if err != nil {
			return nil, fmt.Errorf("unknown 'confidentiality' value of technical asset %q: %v", title, asset.Confidentiality)
		}
		integrity, err := types.ParseCriticality(asset.Integrity)
		if err != nil {
			return nil, fmt.Errorf("unknown 'integrity' value of technical asset %q: %v", title, asset.Integrity)
		}
		availability, err := types.ParseCriticality(asset.Availability)
		if err != nil {
			return nil, fmt.Errorf("unknown 'availability' value of technical asset %q: %v", title, asset.Availability)
		}

		dataFormatsAccepted := make([]types.DataFormat, 0)
		if asset.DataFormatsAccepted != nil {
			for _, dataFormatName := range asset.DataFormatsAccepted {
				dataFormat, err := types.ParseDataFormat(dataFormatName)
				if err != nil {
					return nil, fmt.Errorf("unknown 'data_formats_accepted' value of technical asset %q: %v", title, dataFormatName)
				}
				dataFormatsAccepted = append(dataFormatsAccepted, dataFormat)
			}
		}

		communicationLinks := make([]types.CommunicationLink, 0)
		if asset.CommunicationLinks != nil {
			for commLinkTitle, commLink := range asset.CommunicationLinks {
				weight := 1
				var dataAssetsSent []string
				var dataAssetsReceived []string

				authentication, err := types.ParseAuthentication(commLink.Authentication)
				if err != nil {
					return nil, fmt.Errorf("unknown 'authentication' value of technical asset %q communication link %q: %v", title, commLinkTitle, commLink.Authentication)
				}
				authorization, err := types.ParseAuthorization(commLink.Authorization)
				if err != nil {
					return nil, fmt.Errorf("unknown 'authorization' value of technical asset %q communication link %q: %v", title, commLinkTitle, commLink.Authorization)
				}
				usage, err := types.ParseUsage(commLink.Usage)
				if err != nil {
					return nil, fmt.Errorf("unknown 'usage' value of technical asset %q communication link %q: %v", title, commLinkTitle, commLink.Usage)
				}
				protocol, err := types.ParseProtocol(commLink.Protocol)
				if err != nil {
					return nil, fmt.Errorf("unknown 'protocol' value of technical asset %q communication link %q: %v", title, commLinkTitle, commLink.Protocol)
				}

				if commLink.DataAssetsSent != nil {
					for _, dataAssetSent := range commLink.DataAssetsSent {
						referencedAsset := fmt.Sprintf("%v", dataAssetSent)
						if !contains(dataAssetsSent, referencedAsset) {
							err := parsedModel.CheckDataAssetTargetExists(referencedAsset, fmt.Sprintf("communication link %q of technical asset %q", commLinkTitle, title))
							if err != nil {
								return nil, err
							}

							dataAssetsSent = append(dataAssetsSent, referencedAsset)
							if !contains(dataAssetsProcessed, referencedAsset) {
								dataAssetsProcessed = append(dataAssetsProcessed, referencedAsset)
							}
						}
					}
				}

				if commLink.DataAssetsReceived != nil {
					for _, dataAssetReceived := range commLink.DataAssetsReceived {
						referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
						if contains(dataAssetsReceived, referencedAsset) {
							continue
						}

						err := parsedModel.CheckDataAssetTargetExists(referencedAsset, "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
						if err != nil {
							return nil, err
						}
						dataAssetsReceived = append(dataAssetsReceived, referencedAsset)

						if !contains(dataAssetsProcessed, referencedAsset) {
							dataAssetsProcessed = append(dataAssetsProcessed, referencedAsset)
						}
					}
				}

				if commLink.DiagramTweakWeight > 0 {
					weight = commLink.DiagramTweakWeight
				}

				dataFlowTitle := fmt.Sprintf("%v", commLinkTitle)
				if err != nil {
					return nil, err
				}
				commLinkId, err := createDataFlowId(id, dataFlowTitle)
				if err != nil {
					return nil, err
				}
				tags, err := parsedModel.CheckTags(lowerCaseAndTrim(commLink.Tags), "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
				if err != nil {
					return nil, err
				}
				commLink := types.CommunicationLink{
					Id:                     commLinkId,
					SourceId:               id,
					TargetId:               commLink.Target,
					Title:                  dataFlowTitle,
					Description:            withDefault(commLink.Description, dataFlowTitle),
					Protocol:               protocol,
					Authentication:         authentication,
					Authorization:          authorization,
					Usage:                  usage,
					Tags:                   tags,
					VPN:                    commLink.VPN,
					IpFiltered:             commLink.IpFiltered,
					Readonly:               commLink.Readonly,
					DataAssetsSent:         dataAssetsSent,
					DataAssetsReceived:     dataAssetsReceived,
					DiagramTweakWeight:     weight,
					DiagramTweakConstraint: !commLink.DiagramTweakConstraint,
				}
				communicationLinks = append(communicationLinks, commLink)
				// track all comm links
				parsedModel.CommunicationLinks[commLink.Id] = commLink
				// keep track of map of *all* comm links mapped by target-id (to be able to look up "who is calling me" kind of things)
				parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[commLink.TargetId] = append(
					parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[commLink.TargetId], commLink)
			}
		}

		err = checkIdSyntax(id)
		if err != nil {
			return nil, err
		}
		if _, exists := parsedModel.TechnicalAssets[id]; exists {
			return nil, fmt.Errorf("duplicate id used: %v", id)
		}
		tags, err := parsedModel.CheckTags(lowerCaseAndTrim(asset.Tags), fmt.Sprintf("technical asset %q", title))
		if err != nil {
			return nil, err
		}
		parsedModel.TechnicalAssets[id] = types.TechnicalAsset{
			Id:                      id,
			Usage:                   usage,
			Title:                   title, //fmt.Sprintf("%v", asset["title"]),
			Description:             withDefault(fmt.Sprintf("%v", asset.Description), title),
			Type:                    technicalAssetType,
			Size:                    technicalAssetSize,
			Technology:              technicalAssetTechnology,
			Tags:                    tags,
			Machine:                 technicalAssetMachine,
			Internet:                asset.Internet,
			Encryption:              encryption,
			MultiTenant:             asset.MultiTenant,
			Redundant:               asset.Redundant,
			CustomDevelopedParts:    asset.CustomDevelopedParts,
			UsedAsClientByHuman:     asset.UsedAsClientByHuman,
			OutOfScope:              asset.OutOfScope,
			JustificationOutOfScope: fmt.Sprintf("%v", asset.JustificationOutOfScope),
			Owner:                   fmt.Sprintf("%v", asset.Owner),
			Confidentiality:         confidentiality,
			Integrity:               integrity,
			Availability:            availability,
			JustificationCiaRating:  fmt.Sprintf("%v", asset.JustificationCiaRating),
			DataAssetsProcessed:     dataAssetsProcessed,
			DataAssetsStored:        dataAssetsStored,
			DataFormatsAccepted:     dataFormatsAccepted,
			CommunicationLinks:      communicationLinks,
			DiagramTweakOrder:       asset.DiagramTweakOrder,
		}
	}

	// If CIA is lower than that of its data assets, it is implicitly set to the highest CIA value of its data assets
	for id, techAsset := range parsedModel.TechnicalAssets {
		dataAssetConfidentiality := techAsset.HighestConfidentiality(&parsedModel)
		if techAsset.Confidentiality < dataAssetConfidentiality {
			techAsset.Confidentiality = dataAssetConfidentiality
		}

		dataAssetIntegrity := techAsset.HighestIntegrity(&parsedModel)
		if techAsset.Integrity < dataAssetIntegrity {
			techAsset.Integrity = dataAssetIntegrity
		}

		dataAssetAvailability := techAsset.HighestAvailability(&parsedModel)
		if techAsset.Availability < dataAssetAvailability {
			techAsset.Availability = dataAssetAvailability
		}

		parsedModel.TechnicalAssets[id] = techAsset
	}

	// A target of a communication link implicitly processes all data assets that are sent to or received by that target
	for id, techAsset := range parsedModel.TechnicalAssets {
		for _, commLink := range techAsset.CommunicationLinks {
			if commLink.TargetId == id {
				continue
			}
			targetTechAsset := parsedModel.TechnicalAssets[commLink.TargetId]
			dataAssetsProcessedByTarget := targetTechAsset.DataAssetsProcessed
			for _, dataAssetSent := range commLink.DataAssetsSent {
				if !contains(dataAssetsProcessedByTarget, dataAssetSent) {
					dataAssetsProcessedByTarget = append(dataAssetsProcessedByTarget, dataAssetSent)
				}
			}
			for _, dataAssetReceived := range commLink.DataAssetsReceived {
				if !contains(dataAssetsProcessedByTarget, dataAssetReceived) {
					dataAssetsProcessedByTarget = append(dataAssetsProcessedByTarget, dataAssetReceived)
				}
			}
			targetTechAsset.DataAssetsProcessed = dataAssetsProcessedByTarget
			parsedModel.TechnicalAssets[commLink.TargetId] = targetTechAsset
		}
	}

	// Trust Boundaries ===============================================================================
	checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries := make(map[string]bool)
	parsedModel.TrustBoundaries = make(map[string]types.TrustBoundary)
	for title, boundary := range modelInput.TrustBoundaries {
		id := fmt.Sprintf("%v", boundary.ID)

		var technicalAssetsInside = make([]string, 0)
		if boundary.TechnicalAssetsInside != nil {
			parsedInsideAssets := boundary.TechnicalAssetsInside
			technicalAssetsInside = make([]string, len(parsedInsideAssets))
			for i, parsedInsideAsset := range parsedInsideAssets {
				technicalAssetsInside[i] = fmt.Sprintf("%v", parsedInsideAsset)
				_, found := parsedModel.TechnicalAssets[technicalAssetsInside[i]]
				if !found {
					return nil, fmt.Errorf("missing referenced technical asset %q at trust boundary %q", technicalAssetsInside[i], title)
				}
				if checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries[technicalAssetsInside[i]] {
					return nil, fmt.Errorf("referenced technical asset %q at trust boundary %q is modeled in multiple trust boundaries", technicalAssetsInside[i], title)
				}
				checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries[technicalAssetsInside[i]] = true
				//fmt.Println("asset "+technicalAssetsInside[i]+" at i="+strconv.Itoa(i))
			}
		}

		var trustBoundariesNested = make([]string, 0)
		if boundary.TrustBoundariesNested != nil {
			parsedNestedBoundaries := boundary.TrustBoundariesNested
			trustBoundariesNested = make([]string, len(parsedNestedBoundaries))
			for i, parsedNestedBoundary := range parsedNestedBoundaries {
				trustBoundariesNested[i] = fmt.Sprintf("%v", parsedNestedBoundary)
			}
		}

		trustBoundaryType, err := types.ParseTrustBoundary(boundary.Type)
		if err != nil {
			return nil, fmt.Errorf("unknown 'type' of trust boundary %q: %v", title, boundary.Type)
		}
		tags, err := parsedModel.CheckTags(lowerCaseAndTrim(boundary.Tags), fmt.Sprintf("trust boundary %q", title))
		if err != nil {
			return nil, err
		}
		trustBoundary := types.TrustBoundary{
			Id:                    id,
			Title:                 title, //fmt.Sprintf("%v", boundary["title"]),
			Description:           withDefault(fmt.Sprintf("%v", boundary.Description), title),
			Type:                  trustBoundaryType,
			Tags:                  tags,
			TechnicalAssetsInside: technicalAssetsInside,
			TrustBoundariesNested: trustBoundariesNested,
		}
		err = checkIdSyntax(id)
		if err != nil {
			return nil, err
		}
		if _, exists := parsedModel.TrustBoundaries[id]; exists {
			return nil, fmt.Errorf("duplicate id used: %v", id)
		}
		parsedModel.TrustBoundaries[id] = trustBoundary
		for _, technicalAsset := range trustBoundary.TechnicalAssetsInside {
			parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[technicalAsset] = trustBoundary
			//fmt.Println("Asset "+technicalAsset+" is directly in trust boundary "+trustBoundary.Id)
		}
	}
	err = parsedModel.CheckNestedTrustBoundariesExisting()
	if err != nil {
		return nil, err
	}

	// Shared Runtime ===============================================================================
	parsedModel.SharedRuntimes = make(map[string]types.SharedRuntime)
	for title, inputRuntime := range modelInput.SharedRuntimes {
		id := fmt.Sprintf("%v", inputRuntime.ID)

		var technicalAssetsRunning = make([]string, 0)
		if inputRuntime.TechnicalAssetsRunning != nil {
			parsedRunningAssets := inputRuntime.TechnicalAssetsRunning
			technicalAssetsRunning = make([]string, len(parsedRunningAssets))
			for i, parsedRunningAsset := range parsedRunningAssets {
				assetId := fmt.Sprintf("%v", parsedRunningAsset)
				err := parsedModel.CheckTechnicalAssetExists(assetId, "shared runtime '"+title+"'", false)
				if err != nil {
					return nil, err
				}
				technicalAssetsRunning[i] = assetId
			}
		}
		tags, err := parsedModel.CheckTags(lowerCaseAndTrim(inputRuntime.Tags), "shared runtime '"+title+"'")
		if err != nil {
			return nil, err
		}
		sharedRuntime := types.SharedRuntime{
			Id:                     id,
			Title:                  title, //fmt.Sprintf("%v", boundary["title"]),
			Description:            withDefault(fmt.Sprintf("%v", inputRuntime.Description), title),
			Tags:                   tags,
			TechnicalAssetsRunning: technicalAssetsRunning,
		}
		err = checkIdSyntax(id)
		if err != nil {
			return nil, err
		}
		if _, exists := parsedModel.SharedRuntimes[id]; exists {
			return nil, fmt.Errorf("duplicate id used: %v", id)
		}
		parsedModel.SharedRuntimes[id] = sharedRuntime
	}

	parsedModel.BuiltInRiskCategories = make(map[string]types.RiskCategory)
	for _, rule := range builtinRiskRules {
		category := rule.Category()
		parsedModel.BuiltInRiskCategories[category.Id] = category
	}

	parsedModel.IndividualRiskCategories = make(map[string]types.RiskCategory)
	for _, rule := range customRiskRules {
		parsedModel.IndividualRiskCategories[rule.Category.Id] = rule.Category
	}

	// Individual Risk Categories (just used as regular risk categories) ===============================================================================
	//	parsedModel.IndividualRiskCategories = make(map[string]types.RiskCategory)
	for title, individualCategory := range modelInput.IndividualRiskCategories {
		id := fmt.Sprintf("%v", individualCategory.ID)

		function, err := types.ParseRiskFunction(individualCategory.Function)
		if err != nil {
			return nil, fmt.Errorf("unknown 'function' value of individual risk category %q: %v", title, individualCategory.Function)
		}
		stride, err := types.ParseSTRIDE(individualCategory.STRIDE)
		if err != nil {
			return nil, fmt.Errorf("unknown 'stride' value of individual risk category  %q: %v", title, individualCategory.STRIDE)
		}

		cat := types.RiskCategory{
			Id:                         id,
			Title:                      title,
			Description:                withDefault(fmt.Sprintf("%v", individualCategory.Description), title),
			Impact:                     fmt.Sprintf("%v", individualCategory.Impact),
			ASVS:                       fmt.Sprintf("%v", individualCategory.ASVS),
			CheatSheet:                 fmt.Sprintf("%v", individualCategory.CheatSheet),
			Action:                     fmt.Sprintf("%v", individualCategory.Action),
			Mitigation:                 fmt.Sprintf("%v", individualCategory.Mitigation),
			Check:                      fmt.Sprintf("%v", individualCategory.Check),
			DetectionLogic:             fmt.Sprintf("%v", individualCategory.DetectionLogic),
			RiskAssessment:             fmt.Sprintf("%v", individualCategory.RiskAssessment),
			FalsePositives:             fmt.Sprintf("%v", individualCategory.FalsePositives),
			Function:                   function,
			STRIDE:                     stride,
			ModelFailurePossibleReason: individualCategory.ModelFailurePossibleReason,
			CWE:                        individualCategory.CWE,
		}
		err = checkIdSyntax(id)
		if err != nil {
			return nil, err
		}
		if _, exists := parsedModel.IndividualRiskCategories[id]; exists {
			return nil, fmt.Errorf("duplicate id used: %v", id)
		}
		parsedModel.IndividualRiskCategories[id] = cat

		// NOW THE INDIVIDUAL RISK INSTANCES:
		//individualRiskInstances := make([]model.Risk, 0)
		if individualCategory.RisksIdentified != nil { // TODO: also add syntax checks of input YAML when linked asset is not found or when synthetic-id is already used...
			for title, individualRiskInstance := range individualCategory.RisksIdentified {
				var mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string
				var dataBreachProbability types.DataBreachProbability
				var dataBreachTechnicalAssetIDs []string
				severity, err := types.ParseRiskSeverity(individualRiskInstance.Severity)
				if err != nil {
					return nil, fmt.Errorf("unknown 'severity' value of individual risk instance %q: %v", title, individualRiskInstance.Severity)
				}
				exploitationLikelihood, err := types.ParseRiskExploitationLikelihood(individualRiskInstance.ExploitationLikelihood)
				if err != nil {
					return nil, fmt.Errorf("unknown 'exploitation_likelihood' value of individual risk instance %q: %v", title, individualRiskInstance.ExploitationLikelihood)
				}
				exploitationImpact, err := types.ParseRiskExploitationImpact(individualRiskInstance.ExploitationImpact)
				if err != nil {
					return nil, fmt.Errorf("unknown 'exploitation_impact' value of individual risk instance %q: %v", title, individualRiskInstance.ExploitationImpact)
				}

				if len(individualRiskInstance.MostRelevantDataAsset) > 0 {
					mostRelevantDataAssetId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantDataAsset)
					err := parsedModel.CheckDataAssetTargetExists(mostRelevantDataAssetId, fmt.Sprintf("individual risk %q", title))
					if err != nil {
						return nil, err
					}
				}

				if len(individualRiskInstance.MostRelevantTechnicalAsset) > 0 {
					mostRelevantTechnicalAssetId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantTechnicalAsset)
					err := parsedModel.CheckTechnicalAssetExists(mostRelevantTechnicalAssetId, fmt.Sprintf("individual risk %q", title), false)
					if err != nil {
						return nil, err
					}
				}

				if len(individualRiskInstance.MostRelevantCommunicationLink) > 0 {
					mostRelevantCommunicationLinkId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantCommunicationLink)
					err := parsedModel.CheckCommunicationLinkExists(mostRelevantCommunicationLinkId, fmt.Sprintf("individual risk %q", title))
					if err != nil {
						return nil, err
					}
				}

				if len(individualRiskInstance.MostRelevantTrustBoundary) > 0 {
					mostRelevantTrustBoundaryId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantTrustBoundary)
					err := parsedModel.CheckTrustBoundaryExists(mostRelevantTrustBoundaryId, fmt.Sprintf("individual risk %q", title))
					if err != nil {
						return nil, err
					}
				}

				if len(individualRiskInstance.MostRelevantSharedRuntime) > 0 {
					mostRelevantSharedRuntimeId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantSharedRuntime)
					err := parsedModel.CheckSharedRuntimeExists(mostRelevantSharedRuntimeId, fmt.Sprintf("individual risk %q", title))
					if err != nil {
						return nil, err
					}
				}

				dataBreachProbability, err = types.ParseDataBreachProbability(individualRiskInstance.DataBreachProbability)
				if err != nil {
					return nil, fmt.Errorf("unknown 'data_breach_probability' value of individual risk instance %q: %v", title, individualRiskInstance.DataBreachProbability)
				}

				if individualRiskInstance.DataBreachTechnicalAssets != nil {
					dataBreachTechnicalAssetIDs = make([]string, len(individualRiskInstance.DataBreachTechnicalAssets))
					for i, parsedReferencedAsset := range individualRiskInstance.DataBreachTechnicalAssets {
						assetId := fmt.Sprintf("%v", parsedReferencedAsset)
						err := parsedModel.CheckTechnicalAssetExists(assetId, fmt.Sprintf("data breach technical assets of individual risk %q", title), false)
						if err != nil {
							return nil, err
						}
						dataBreachTechnicalAssetIDs[i] = assetId
					}
				}

				parsedModel.GeneratedRisksByCategory[cat.Id] = append(parsedModel.GeneratedRisksByCategory[cat.Id], types.Risk{
					SyntheticId:                     createSyntheticId(cat.Id, mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId),
					Title:                           fmt.Sprintf("%v", title),
					CategoryId:                      cat.Id,
					Severity:                        severity,
					ExploitationLikelihood:          exploitationLikelihood,
					ExploitationImpact:              exploitationImpact,
					MostRelevantDataAssetId:         mostRelevantDataAssetId,
					MostRelevantTechnicalAssetId:    mostRelevantTechnicalAssetId,
					MostRelevantCommunicationLinkId: mostRelevantCommunicationLinkId,
					MostRelevantTrustBoundaryId:     mostRelevantTrustBoundaryId,
					MostRelevantSharedRuntimeId:     mostRelevantSharedRuntimeId,
					DataBreachProbability:           dataBreachProbability,
					DataBreachTechnicalAssetIDs:     dataBreachTechnicalAssetIDs,
				})
			}
		}
	}

	// Risk Tracking ===============================================================================
	parsedModel.RiskTracking = make(map[string]types.RiskTracking)
	for syntheticRiskId, riskTracking := range modelInput.RiskTracking {
		justification := fmt.Sprintf("%v", riskTracking.Justification)
		checkedBy := fmt.Sprintf("%v", riskTracking.CheckedBy)
		ticket := fmt.Sprintf("%v", riskTracking.Ticket)
		var date time.Time
		if len(riskTracking.Date) > 0 {
			var parseError error
			date, parseError = time.Parse("2006-01-02", riskTracking.Date)
			if parseError != nil {
				return nil, fmt.Errorf("unable to parse 'date' of risk tracking %q: %v", syntheticRiskId, riskTracking.Date)
			}
		}

		status, err := types.ParseRiskStatus(riskTracking.Status)
		if err != nil {
			return nil, fmt.Errorf("unknown 'status' value of risk tracking %q: %v", syntheticRiskId, riskTracking.Status)
		}

		tracking := types.RiskTracking{
			SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
			Justification:   justification,
			CheckedBy:       checkedBy,
			Ticket:          ticket,
			Date:            types.Date{Time: date},
			Status:          status,
		}

		parsedModel.RiskTracking[syntheticRiskId] = tracking
	}

	// ====================== model consistency check (linking)
	for _, technicalAsset := range parsedModel.TechnicalAssets {
		for _, commLink := range technicalAsset.CommunicationLinks {
			err := parsedModel.CheckTechnicalAssetExists(commLink.TargetId, "communication link '"+commLink.Title+"' of technical asset '"+technicalAsset.Title+"'", false)
			if err != nil {
				return nil, err
			}
		}
	}

	/*
		data, _ := json.MarshalIndent(parsedModel, "", "  ")
		_ = os.WriteFile(filepath.Join("all.json"), data, 0644)
	*/

	/**
	inYamlData, _ := yaml.Marshal(modelInput)
	_ = os.WriteFile(filepath.Join("in.yaml"), inYamlData, 0644)

	inJsonData, _ := json.MarshalIndent(modelInput, "", "  ")
	_ = os.WriteFile(filepath.Join("in.json"), inJsonData, 0644)

	outYamlData, _ := yaml.Marshal(parsedModel)
	_ = os.WriteFile(filepath.Join("out.yaml"), outYamlData, 0644)

	outJsonData, _ := json.MarshalIndent(parsedModel, "", "  ")
	_ = os.WriteFile(filepath.Join("out.json"), outJsonData, 0644)
	/**/

	return &parsedModel, nil
}

func checkIdSyntax(id string) error {
	validIdSyntax := regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)
	if !validIdSyntax.MatchString(id) {
		return fmt.Errorf("invalid id syntax used (only letters, numbers, and hyphen allowed): %v", id)
	}
	return nil
}

func createDataFlowId(sourceAssetId, title string) (string, error) {
	reg, err := regexp.Compile("[^A-Za-z0-9]+")
	if err != nil {
		return "", err
	}
	return sourceAssetId + ">" + strings.Trim(reg.ReplaceAllString(strings.ToLower(title), "-"), "- "), nil
}

func createSyntheticId(categoryId string,
	mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string) string {
	result := categoryId
	if len(mostRelevantTechnicalAssetId) > 0 {
		result += "@" + mostRelevantTechnicalAssetId
	}
	if len(mostRelevantCommunicationLinkId) > 0 {
		result += "@" + mostRelevantCommunicationLinkId
	}
	if len(mostRelevantTrustBoundaryId) > 0 {
		result += "@" + mostRelevantTrustBoundaryId
	}
	if len(mostRelevantSharedRuntimeId) > 0 {
		result += "@" + mostRelevantSharedRuntimeId
	}
	if len(mostRelevantDataAssetId) > 0 {
		result += "@" + mostRelevantDataAssetId
	}
	return result
}

// in order to prevent Path-Traversal like stuff...
func removePathElementsFromImageFiles(overview input.Overview) input.Overview {
	for i := range overview.Images {
		newValue := make(map[string]string)
		for file, desc := range overview.Images[i] {
			newValue[filepath.Base(file)] = desc
		}
		overview.Images[i] = newValue
	}
	return overview
}

func withDefault(value string, defaultWhenEmpty string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > 0 && trimmed != "<nil>" {
		return trimmed
	}
	return strings.TrimSpace(defaultWhenEmpty)
}

func lowerCaseAndTrim(tags []string) []string {
	for i := range tags {
		tags[i] = strings.ToLower(strings.TrimSpace(tags[i]))
	}
	return tags
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
