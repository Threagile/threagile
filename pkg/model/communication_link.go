/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package model

import (
	"fmt"
	"sort"

	"github.com/threagile/threagile/pkg/colors"
	"github.com/threagile/threagile/pkg/security/types"
)

type CommunicationLink struct {
	Id, SourceId, TargetId, Title, Description string
	Protocol                                   types.Protocol
	Tags                                       []string
	VPN, IpFiltered, Readonly                  bool
	Authentication                             types.Authentication
	Authorization                              types.Authorization
	Usage                                      types.Usage
	DataAssetsSent, DataAssetsReceived         []string
	DiagramTweakWeight                         int
	DiagramTweakConstraint                     bool
}

func (what CommunicationLink) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what CommunicationLink) IsTaggedWithBaseTag(baseTag string) bool {
	return IsTaggedWithBaseTag(what.Tags, baseTag)
}

func (what CommunicationLink) IsAcrossTrustBoundary(parsedModel *ParsedModel) bool {
	trustBoundaryOfSourceAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.SourceId]
	trustBoundaryOfTargetAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.TargetId]
	return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id
}

func (what CommunicationLink) IsAcrossTrustBoundaryNetworkOnly(parsedModel *ParsedModel) bool {
	trustBoundaryOfSourceAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.SourceId]
	if !trustBoundaryOfSourceAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfSourceAsset = parsedModel.TrustBoundaries[trustBoundaryOfSourceAsset.ParentTrustBoundaryID(parsedModel)]
	}
	trustBoundaryOfTargetAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.TargetId]
	if !trustBoundaryOfTargetAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfTargetAsset = parsedModel.TrustBoundaries[trustBoundaryOfTargetAsset.ParentTrustBoundaryID(parsedModel)]
	}
	return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id && trustBoundaryOfTargetAsset.Type.IsNetworkBoundary()
}

func (what CommunicationLink) HighestConfidentiality(parsedModel *ParsedModel) types.Confidentiality {
	highest := types.Public
	for _, dataId := range what.DataAssetsSent {
		dataAsset := parsedModel.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := parsedModel.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	return highest
}

func (what CommunicationLink) HighestIntegrity(parsedModel *ParsedModel) types.Criticality {
	highest := types.Archive
	for _, dataId := range what.DataAssetsSent {
		dataAsset := parsedModel.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := parsedModel.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	return highest
}

func (what CommunicationLink) HighestAvailability(parsedModel *ParsedModel) types.Criticality {
	highest := types.Archive
	for _, dataId := range what.DataAssetsSent {
		dataAsset := parsedModel.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := parsedModel.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	return highest
}

func (what CommunicationLink) DataAssetsSentSorted(parsedModel *ParsedModel) []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsSent {
		result = append(result, parsedModel.DataAssets[assetID])
	}
	sort.Sort(byDataAssetTitleSort(result))
	return result
}

func (what CommunicationLink) DataAssetsReceivedSorted(parsedModel *ParsedModel) []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsReceived {
		result = append(result, parsedModel.DataAssets[assetID])
	}
	sort.Sort(byDataAssetTitleSort(result))
	return result
}

func (what CommunicationLink) IsBidirectional() bool {
	return len(what.DataAssetsSent) > 0 && len(what.DataAssetsReceived) > 0
}

// === Style stuff =======================================

// Line Styles:

// dotted when model forgery attempt (i.e. nothing being sent and received)

func (what CommunicationLink) DetermineArrowLineStyle() string {
	if len(what.DataAssetsSent) == 0 && len(what.DataAssetsReceived) == 0 {
		return "dotted" // dotted, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	if what.Usage == types.DevOps {
		return "dashed"
	}
	return "solid"
}

// Pen Widths:

func (what CommunicationLink) DetermineArrowPenWidth(parsedModel *ParsedModel) string {
	if what.DetermineArrowColor(parsedModel) == colors.Pink {
		return fmt.Sprintf("%f", 3.0)
	}
	if what.DetermineArrowColor(parsedModel) != colors.Black {
		return fmt.Sprintf("%f", 2.5)
	}
	return fmt.Sprintf("%f", 1.5)
}

func (what CommunicationLink) DetermineLabelColor(parsedModel *ParsedModel) string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	/*
		if dataFlow.Protocol.IsEncrypted() {
			return colors.Gray
		} else {*/
	// check for red
	for _, sentDataAsset := range what.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Integrity == types.MissionCritical {
			return colors.Red
		}
	}
	for _, receivedDataAsset := range what.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Integrity == types.MissionCritical {
			return colors.Red
		}
	}
	// check for amber
	for _, sentDataAsset := range what.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Integrity == types.Critical {
			return colors.Amber
		}
	}
	for _, receivedDataAsset := range what.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Integrity == types.Critical {
			return colors.Amber
		}
	}
	// default
	return colors.Gray

}

// pink when model forgery attempt (i.e. nothing being sent and received)

func (what CommunicationLink) DetermineArrowColor(parsedModel *ParsedModel) string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	if len(what.DataAssetsSent) == 0 && len(what.DataAssetsReceived) == 0 ||
		what.Protocol == types.UnknownProtocol {
		return colors.Pink // pink, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	if what.Usage == types.DevOps {
		return colors.MiddleLightGray
	} else if what.VPN {
		return colors.DarkBlue
	} else if what.IpFiltered {
		return colors.Brown
	}
	// check for red
	for _, sentDataAsset := range what.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Confidentiality == types.StrictlyConfidential {
			return colors.Red
		}
	}
	for _, receivedDataAsset := range what.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Confidentiality == types.StrictlyConfidential {
			return colors.Red
		}
	}
	// check for amber
	for _, sentDataAsset := range what.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Confidentiality == types.Confidential {
			return colors.Amber
		}
	}
	for _, receivedDataAsset := range what.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Confidentiality == types.Confidential {
			return colors.Amber
		}
	}
	// default
	return colors.Black
	/*
		} else if dataFlow.Authentication != NoneAuthentication {
			return colors.Black
		} else {
			// check for red
			for _, sentDataAsset := range dataFlow.DataAssetsSent { // first check if any red?
				if ParsedModelRoot.DataAssets[sentDataAsset].Integrity == MissionCritical {
					return colors.Red
				}
			}
			for _, receivedDataAsset := range dataFlow.DataAssetsReceived { // first check if any red?
				if ParsedModelRoot.DataAssets[receivedDataAsset].Integrity == MissionCritical {
					return colors.Red
				}
			}
			// check for amber
			for _, sentDataAsset := range dataFlow.DataAssetsSent { // then check if any amber?
				if ParsedModelRoot.DataAssets[sentDataAsset].Integrity == Critical {
					return colors.Amber
				}
			}
			for _, receivedDataAsset := range dataFlow.DataAssetsReceived { // then check if any amber?
				if ParsedModelRoot.DataAssets[receivedDataAsset].Integrity == Critical {
					return colors.Amber
				}
			}
			return colors.Black
		}
	*/
}

type ByTechnicalCommunicationLinkIdSort []CommunicationLink

func (what ByTechnicalCommunicationLinkIdSort) Len() int      { return len(what) }
func (what ByTechnicalCommunicationLinkIdSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalCommunicationLinkIdSort) Less(i, j int) bool {
	return what[i].Id > what[j].Id
}

type ByTechnicalCommunicationLinkTitleSort []CommunicationLink

func (what ByTechnicalCommunicationLinkTitleSort) Len() int      { return len(what) }
func (what ByTechnicalCommunicationLinkTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalCommunicationLinkTitleSort) Less(i, j int) bool {
	return what[i].Title > what[j].Title
}
