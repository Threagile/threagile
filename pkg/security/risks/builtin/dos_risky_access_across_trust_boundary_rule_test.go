package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksTechAssetNotLoadBalancerNotRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.LoadBalancer: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksTechAssetLessCriticalAvailabilityNotRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Availability: types.Important,
				Technologies: types.TechnologyList{
					{
						Name: "elb",
						Attributes: map[string]bool{
							types.LoadBalancer: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksDirectAccessDevOpsUsageNotRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:           "ta1",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"ta2": {
				Id:           "ta2",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
					Usage:    types.DevOps,
				},
			},
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": {
				Id:   "tb1",
				Type: types.NetworkCloudProvider,
			},
			"ta2": {
				Id:   "tb2",
				Type: types.NetworkCloudProvider,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksDirectAccessUsingLocalProcessProtocolNotRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:           "ta1",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"ta2": {
				Id:           "ta2",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
					Usage:    types.Business,
					Protocol: types.LocalFileAccess,
				},
			},
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": {
				Id:   "tb1",
				Type: types.NetworkCloudProvider,
			},
			"ta2": {
				Id:   "tb2",
				Type: types.NetworkCloudProvider,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksDirectAccessUsingHTTPNotAcrossTrustBoundaryNetworkProtocolNotRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:           "ta1",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"ta2": {
				Id:           "ta2",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
					Usage:    types.Business,
					Protocol: types.HTTP,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksAcrossTestBoundaryDevOpsNonLocalProcessRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:           "ta1",
				Title:        "First Web Application",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"ta2": {
				Id:           "ta2",
				Title:        "Second Web Application",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
					Title:    "Direct Call",
					Usage:    types.Business,
					Protocol: types.HTTP,
				},
			},
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": {
				Id:   "tb1",
				Type: types.NetworkCloudProvider,
			},
			"ta2": {
				Id:   "tb2",
				Type: types.NetworkCloudProvider,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, 1, len(risks))
	assert.Equal(t, "<b>Denial-of-Service</b> risky access of <b>First Web Application</b> by <b>Second Web Application</b> via <b>Direct Call</b>", risks[0].Title)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksMissionCriticalHighRiskRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:           "ta1",
				Title:        "First Web Application",
				Availability: types.MissionCritical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
				Redundant: false,
			},
			"ta2": {
				Id:           "ta2",
				Title:        "Second Web Application",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
					Title:    "Direct Call",
					Usage:    types.Business,
					Protocol: types.HTTP,
				},
			},
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": {
				Id:   "tb1",
				Type: types.NetworkCloudProvider,
			},
			"ta2": {
				Id:   "tb2",
				Type: types.NetworkCloudProvider,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, 1, len(risks))
	assert.Equal(t, "<b>Denial-of-Service</b> risky access of <b>First Web Application</b> by <b>Second Web Application</b> via <b>Direct Call</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestDosRiskyAccessAcrossTrustBoundaryRuleGenerateRisksWithLoadBalancerMultipleRisksCreated(t *testing.T) {
	rule := NewDosRiskyAccessAcrossTrustBoundaryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:           "ta1",
				Title:        "First Web Application",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"elb": {
				Id:           "elb",
				Title:        "Load balancer",
				Availability: types.MissionCritical,
				Technologies: types.TechnologyList{
					{
						Name: "load-balancer",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: true,
						},
					},
				},
			},
			"ta2": {
				Id:           "ta2",
				Title:        "Second Web Application",
				Availability: types.Critical,
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"elb": {
				{
					Id:       "elb",
					TargetId: "elb",
					SourceId: "ta1",
					Title:    "Call to load balancer",
					Usage:    types.Business,
					Protocol: types.HTTP,
				},
			},
			"ta2": {
				{
					Id:       "ta2",
					TargetId: "ta2",
					SourceId: "elb",
					Title:    "Forwarded call to second web application",
					Usage:    types.Business,
					Protocol: types.HTTP,
				},
			},
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": {
				Id:   "tb1",
				Type: types.NetworkCloudProvider,
			},
			"elb": {
				Id:   "tb2",
				Type: types.NetworkCloudProvider,
			},
			"ta2": {
				Id:   "tb2",
				Type: types.NetworkCloudProvider,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, 2, len(risks))
	assert.Equal(t, "<b>Denial-of-Service</b> risky access of <b>Load balancer</b> by <b>First Web Application</b> via <b>Call to load balancer</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Denial-of-Service</b> risky access of <b>Second Web Application</b> by <b>First Web Application</b> via <b>Call to load balancer</b> forwarded via <b>Load balancer</b>", risks[1].Title)
	assert.Equal(t, types.LowImpact, risks[1].ExploitationImpact)
}
