/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IsAcrossTrustBoundary_EmptyDataReturnTrue(t *testing.T) {
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{}

	result := communicationLink.IsAcrossTrustBoundary(parsedModel)

	assert.True(t, result)
}

func Test_IsAcrossTrustBoundary_NoSourceIdReturnFalse(t *testing.T) {
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*TrustBoundary{},
	}

	result := communicationLink.IsAcrossTrustBoundary(parsedModel)

	assert.True(t, result)
}

func Test_IsAcrossTrustBoundary_NoTargetIdReturnFalse(t *testing.T) {
	trustBoundary := TrustBoundary{
		Id: "trust-boundary",
	}
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*TrustBoundary{
			"source": &trustBoundary,
		},
	}

	result := communicationLink.IsAcrossTrustBoundary(parsedModel)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundary_CompareTrustBoundaryIds(t *testing.T) {
	trustBoundary := TrustBoundary{
		Id: "trust-boundary",
	}
	anotherTrustBoundary := TrustBoundary{
		Id: "another-trust-boundary",
	}
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*TrustBoundary{
			"source": &trustBoundary,
			"target": &anotherTrustBoundary,
		},
	}

	result := communicationLink.IsAcrossTrustBoundary(parsedModel)

	assert.True(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_EmptyDataReturnFalse(t *testing.T) {
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{}

	result := communicationLink.IsAcrossTrustBoundaryNetworkOnly(parsedModel)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_NoSourceIdReturnFalse(t *testing.T) {
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*TrustBoundary{},
	}

	result := communicationLink.IsAcrossTrustBoundaryNetworkOnly(parsedModel)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_SourceIdIsNotNetworkBoundaryReturnFalse(t *testing.T) {
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*TrustBoundary{
			"source": {
				Id:   "trust-boundary",
				Type: ExecutionEnvironment,
			},
		},
	}

	result := communicationLink.IsAcrossTrustBoundaryNetworkOnly(parsedModel)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_NoTargetIdReturnFalse(t *testing.T) {
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*TrustBoundary{
			"source": {
				Id: "trust-boundary",
			},
		},
	}

	result := communicationLink.IsAcrossTrustBoundaryNetworkOnly(parsedModel)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_TargetIdIsNotNetworkBoundaryReturnFalse(t *testing.T) {
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*TrustBoundary{
			"source": {
				Id: "trust-boundary",
			},
			"target": {
				Id:   "trust-boundary",
				Type: ExecutionEnvironment,
			},
		},
	}

	result := communicationLink.IsAcrossTrustBoundaryNetworkOnly(parsedModel)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_Compare(t *testing.T) {
	trustBoundary := TrustBoundary{
		Id: "trust-boundary",
	}
	anotherTrustBoundary := TrustBoundary{
		Id: "another-trust-boundary",
	}
	communicationLink := CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*TrustBoundary{
			"source": &trustBoundary,
			"target": &anotherTrustBoundary,
		},
	}

	result := communicationLink.IsAcrossTrustBoundaryNetworkOnly(parsedModel)

	assert.True(t, result)
}
