/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"sort"
)

type CommunicationLink struct {
	Id                     string         `json:"id,omitempty" yaml:"id,omitempty"`
	SourceId               string         `json:"source_id,omitempty" yaml:"source_id,omitempty"`
	TargetId               string         `json:"target_id,omitempty" yaml:"target_id,omitempty"`
	Title                  string         `json:"title,omitempty" yaml:"title,omitempty"`
	Description            string         `json:"description,omitempty" yaml:"description,omitempty"`
	Protocol               Protocol       `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Tags                   []string       `json:"tags,omitempty" yaml:"tags,omitempty"`
	VPN                    bool           `json:"vpn,omitempty" yaml:"vpn,omitempty"`
	IpFiltered             bool           `json:"ip_filtered,omitempty" yaml:"ip_filtered,omitempty"`
	Readonly               bool           `json:"readonly,omitempty" yaml:"readonly,omitempty"`
	Authentication         Authentication `json:"authentication,omitempty" yaml:"authentication,omitempty"`
	Authorization          Authorization  `json:"authorization,omitempty" yaml:"authorization,omitempty"`
	Usage                  Usage          `json:"usage,omitempty" yaml:"usage,omitempty"`
	DataAssetsSent         []string       `json:"data_assets_sent,omitempty" yaml:"data_assets_sent,omitempty"`
	DataAssetsReceived     []string       `json:"data_assets_received,omitempty" yaml:"data_assets_received,omitempty"`
	DiagramTweakWeight     int            `json:"diagram_tweak_weight,omitempty" yaml:"diagram_tweak_weight,omitempty"`
	DiagramTweakConstraint bool           `json:"diagram_tweak_constraint,omitempty" yaml:"diagram_tweak_constraint,omitempty"`
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

func (what CommunicationLink) HighestConfidentiality(parsedModel *ParsedModel) Confidentiality {
	highest := Public
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

func (what CommunicationLink) HighestIntegrity(parsedModel *ParsedModel) Criticality {
	highest := Archive
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

func (what CommunicationLink) HighestAvailability(parsedModel *ParsedModel) Criticality {
	highest := Archive
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
