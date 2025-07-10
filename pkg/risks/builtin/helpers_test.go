package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/threagile/threagile/pkg/types"
)

func Test_IsAcrossTrustBoundaryNetworkOnly_EmptyDataReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_NoSourceIdReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_SourceIdIsNotNetworkBoundaryReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		TrustBoundaries: map[string]*types.TrustBoundary{
			"trust-boundary": { 
				Id:                    "trust-boundary",             
				TrustBoundariesNested: []string{"trust-boundary-2"},
			},
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"source": { 
				Id:   "trust-boundary", 
				Type: types.ExecutionEnvironment,
			},
			"target": { 
				Id:   "trust-boundary-2", 
				Type: types.ExecutionEnvironment,
			},
		},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_NoTargetIdReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"source": {
				Id: "trust-boundary",
			},
		},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_TargetIdIsNotNetworkBoundaryReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"source": {
				Id: "trust-boundary",
			},
			"target": {
				Id:   "trust-boundary",
				Type: types.ExecutionEnvironment,
			},
		},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_Compare(t *testing.T) {
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	anotherTrustBoundary := types.TrustBoundary{
		Id: "another-trust-boundary",
	}
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"source": &trustBoundary,
			"target": &anotherTrustBoundary,
		},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.True(t, result)
}

func Test_isSameExecutionEnvironment_EmptyDataReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{}
	parsedModel := &types.Model{}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameExecutionEnvironemnt_NoTrustBoundaryOfMyAssetReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameExecutionEnvironment_NoTrustBoundaryOfOtherAssetReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset": {},
		},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameExecutionEnvironment_TrustBoundariesAreDifferentReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	anotherTrustBoundary := types.TrustBoundary{
		Id: "another-trust-boundary",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &anotherTrustBoundary,
		},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameExecutionEnvironment_TrustBoundariesAreSameReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &trustBoundary,
		},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_EmptyDataReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{}
	parsedModel := &types.Model{}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_NoTrustBoundaryOfMyAssetReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_NoTrustBoundaryOfOtherAssetReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset": {},
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_TrustBoundariesAreDifferentReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	anotherTrustBoundary := types.TrustBoundary{
		Id: "another-trust-boundary",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &anotherTrustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_TrustBoundariesAreSameReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &trustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_TrustBoundariesAreDifferentButParentIsSameReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parentTrustBoundary := types.TrustBoundary{
		Id:                    "parent-trust-boundary",
		TrustBoundariesNested: []string{"trust-boundary", "another-trust-boundary"},
	}
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	anotherTrustBoundary := types.TrustBoundary{
		Id: "another-trust-boundary",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &anotherTrustBoundary,
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"trust-boundary":         &trustBoundary,
			"another-trust-boundary": &anotherTrustBoundary,
			"parent-trust-boundary":  &parentTrustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_TrustBoundariesAreDifferentButParentIsDifferentReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parentTrustBoundary := types.TrustBoundary{
		Id:                    "parent-trust-boundary",
		TrustBoundariesNested: []string{"trust-boundary"},
	}
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	anotherTrustBoundary := types.TrustBoundary{
		Id: "another-trust-boundary",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &anotherTrustBoundary,
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"trust-boundary":         &trustBoundary,
			"another-trust-boundary": &anotherTrustBoundary,
			"parent-trust-boundary":  &parentTrustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_NotNetworkBoundaryReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id:   "trust-boundary",
		Type: types.ExecutionEnvironment,
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &trustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_DifferentNotNetworkBoundaryReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id:                    "trust-boundary",
		Type:                  types.ExecutionEnvironment,
		TechnicalAssetsInside: []string{"asset"},
	}
	trustBoundary2 := types.TrustBoundary{
		Id:                    "trust-boundary-2",
		TechnicalAssetsInside: []string{"other-asset"},
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &trustBoundary2,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_contains(t *testing.T) {
	result := contains([]string{"a", "b"}, "b")

	assert.True(t, result)
}

func Test_contains_NotFoundReturnFalse(t *testing.T) {
	result := contains([]string{"a", "b"}, "c")

	assert.False(t, result)
}

func Test_contains_EmptyDataReturnFalse(t *testing.T) {
	result := contains([]string{}, "c")

	assert.False(t, result)
}
