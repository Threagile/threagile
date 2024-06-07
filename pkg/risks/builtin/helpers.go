package builtin

import (
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

func isAcrossTrustBoundaryNetworkOnly(parsedModel *types.Model, communicationLink *types.CommunicationLink) bool {
	trustBoundaryOfSourceAsset, trustBoundaryOfSourceAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[communicationLink.SourceId]
	if !trustBoundaryOfSourceAssetOk {
		return false
	}
	if !trustBoundaryOfSourceAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfSourceAsset, trustBoundaryOfSourceAssetOk = parsedModel.TrustBoundaries[trustBoundaryOfSourceAsset.ParentTrustBoundaryID(parsedModel)]
		if !trustBoundaryOfSourceAssetOk {
			return false
		}
	}
	trustBoundaryOfTargetAsset, trustBoundaryOfTargetAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[communicationLink.TargetId]
	if !trustBoundaryOfTargetAssetOk {
		return false
	}
	if !trustBoundaryOfTargetAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfTargetAsset, trustBoundaryOfTargetAssetOk = parsedModel.TrustBoundaries[trustBoundaryOfTargetAsset.ParentTrustBoundaryID(parsedModel)]
		if !trustBoundaryOfTargetAssetOk {
			return false
		}
	}
	return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id && trustBoundaryOfTargetAsset.Type.IsNetworkBoundary()
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func containsCaseInsensitiveAny(a []string, x ...string) bool {
	for _, n := range a {
		for _, c := range x {
			if strings.TrimSpace(strings.ToLower(c)) == strings.TrimSpace(strings.ToLower(n)) {
				return true
			}
		}
	}
	return false
}

func isSameExecutionEnvironment(parsedModel *types.Model, ta *types.TechnicalAsset, otherAssetId string) bool {
	trustBoundaryOfMyAsset, trustBoundaryOfMyAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[ta.Id]
	trustBoundaryOfOtherAsset, trustBoundaryOfOtherAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if trustBoundaryOfMyAssetOk != trustBoundaryOfOtherAssetOk {
		return false
	}
	if !trustBoundaryOfMyAssetOk && !trustBoundaryOfOtherAssetOk {
		return true
	}
	if trustBoundaryOfMyAsset.Type == types.ExecutionEnvironment && trustBoundaryOfOtherAsset.Type == types.ExecutionEnvironment {
		return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
	}
	return false
}

func isSameTrustBoundaryNetworkOnly(parsedModel *types.Model, ta *types.TechnicalAsset, otherAssetId string) bool {
	trustBoundaryOfMyAsset, trustBoundaryOfMyAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[ta.Id]
	if trustBoundaryOfMyAsset != nil && !trustBoundaryOfMyAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfMyAsset, trustBoundaryOfMyAssetOk = parsedModel.TrustBoundaries[trustBoundaryOfMyAsset.ParentTrustBoundaryID(parsedModel)]
	}
	trustBoundaryOfOtherAsset, trustBoundaryOfOtherAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if trustBoundaryOfOtherAsset != nil && !trustBoundaryOfOtherAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfOtherAsset, trustBoundaryOfOtherAssetOk = parsedModel.TrustBoundaries[trustBoundaryOfOtherAsset.ParentTrustBoundaryID(parsedModel)]
	}
	if trustBoundaryOfMyAssetOk != trustBoundaryOfOtherAssetOk {
		return false
	}
	if !trustBoundaryOfMyAssetOk && !trustBoundaryOfOtherAssetOk {
		return true
	}
	if trustBoundaryOfMyAsset == nil || trustBoundaryOfOtherAsset == nil {
		return trustBoundaryOfMyAsset == trustBoundaryOfOtherAsset
	}
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}
