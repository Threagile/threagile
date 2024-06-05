/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/

package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/threagile/threagile/pkg/security/types"
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
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"source": {
				Id:   "trust-boundary",
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
