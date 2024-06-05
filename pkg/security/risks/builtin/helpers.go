package builtin

import (
	"github.com/threagile/threagile/pkg/security/types"
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
