package builtin

import (
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

func isAcrossTrustBoundaryNetworkOnly(parsedModel *types.Model, communicationLink *types.CommunicationLink) bool {
	trustBoundaryOfSourceAsset, trustBoundaryOfSourceAssetOk :=
		parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[communicationLink.SourceId]
	if !isNetworkOnly(parsedModel, trustBoundaryOfSourceAssetOk, trustBoundaryOfSourceAsset) {
		return false
	}

	trustBoundaryOfTargetAsset, trustBoundaryOfTargetAssetOk :=
		parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[communicationLink.TargetId]
	if !isNetworkOnly(parsedModel, trustBoundaryOfTargetAssetOk, trustBoundaryOfTargetAsset) {
		return false
	}

	return isAcrossNetworkTrustBoundary(trustBoundaryOfSourceAsset, trustBoundaryOfTargetAsset)
}

func isAcrossNetworkTrustBoundary(
	trustBoundaryOfSourceAsset *types.TrustBoundary, trustBoundaryOfTargetAsset *types.TrustBoundary) bool {
	return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id && trustBoundaryOfTargetAsset.Type.IsNetworkBoundary()
}

func isNetworkOnly(parsedModel *types.Model, trustBoundaryOk bool, trustBoundary *types.TrustBoundary) bool {
	if !trustBoundaryOk {
		return false
	}
	if !trustBoundary.Type.IsNetworkBoundary() { // find and use the parent boundary then
		parentTrustBoundary := parsedModel.FindParentTrustBoundary(trustBoundary)
		if parentTrustBoundary != nil {
			return false
		}
	}
	return true
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
	if !trustBoundaryOfMyAssetOk {
		return true
	}
	if trustBoundaryOfMyAsset.Type == types.ExecutionEnvironment && trustBoundaryOfOtherAsset.Type == types.ExecutionEnvironment {
		return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
	}
	return false
}

func isSameTrustBoundaryNetworkOnly(parsedModel *types.Model, ta *types.TechnicalAsset, otherAssetId string) bool {
	trustBoundaryOfMyAsset, trustBoundaryOfMyAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[ta.Id]
	useParentBoundary(&trustBoundaryOfMyAsset, parsedModel, &trustBoundaryOfMyAssetOk)

	trustBoundaryOfOtherAsset, trustBoundaryOfOtherAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	useParentBoundary(&trustBoundaryOfOtherAsset, parsedModel, &trustBoundaryOfOtherAssetOk)

	if trustBoundaryOfMyAssetOk != trustBoundaryOfOtherAssetOk {
		return false
	}
	if !trustBoundaryOfMyAssetOk {
		return true
	}
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}

func useParentBoundary(trustBoundaryOfAsset **types.TrustBoundary, parsedModel *types.Model, trustBoundaryOfAssetOk *bool) {
	if trustBoundaryOfAsset == nil {
		return
	}
	tb := *trustBoundaryOfAsset
	if tb != nil && !tb.Type.IsNetworkBoundary() {
		*trustBoundaryOfAsset = parsedModel.FindParentTrustBoundary(tb)
		*trustBoundaryOfAssetOk = *trustBoundaryOfAsset != nil
	}
}
