package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingCloudHardeningRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingCloudHardeningRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingCloudHardeningRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingCloudHardeningRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope:           true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingCloudHardeningRuleGenerateRisksTrustBoundaryNotWithinCloudNoRisksCreated(t *testing.T) {
	rule := NewMissingCloudHardeningRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "First Technical Asset Inside Trust Boundary",
				Tags:  []string{"unspecific-cloud"},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Second Technical Asset Inside Trust Boundary",
				Tags:  []string{"unspecific-cloud"},
			},
			"ta3": {
				Id:    "ta3",
				Title: "Technical Asset Outside Trust Boundary",
				Tags:  []string{"unspecific-cloud"},
			},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id:                    "tb1",
				Title:                 "Test Trust Boundary",
				TechnicalAssetsInside: []string{"ta1", "ta2"},
				Tags:                  []string{"unspecific-cloud"},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type CloudHardeningRuleTest struct {
	cloud string

	expectedTitleSuffix   string
	expectedMessageSuffix string
}

func TestMissingCloudHardeningRuleGenerateRisksTrustBoundaryWithoutCloudHardeningRiskCreated(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws": {
			cloud:                 "aws",
			expectedTitleSuffix:   " (AWS)",
			expectedMessageSuffix: ": <u>CIS Benchmark for AWS</u>",
		},
		"azure": {
			cloud:                 "azure",
			expectedTitleSuffix:   " (Azure)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Microsoft Azure</u>",
		},
		"gcp": {
			cloud:                 "gcp",
			expectedTitleSuffix:   " (GCP)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Google Cloud Computing Platform</u>",
		},
		"ocp": {
			cloud:                 "ocp",
			expectedTitleSuffix:   " (OCP)",
			expectedMessageSuffix: ": <u>Vendor Best Practices for Oracle Cloud Platform</u>",
		},
		"unspecific-cloud": {
			cloud: "unspecific-cloud",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "First Technical Asset Inside Trust Boundary",
						Tags:  []string{testCase.cloud},
					},
					"ta2": {
						Id:    "ta2",
						Title: "Second Technical Asset Inside Trust Boundary",
						Tags:  []string{testCase.cloud},
					},
					"ta3": {
						Id:    "ta3",
						Title: "Technical Asset Outside Trust Boundary",
						Tags:  []string{testCase.cloud},
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"tb1": {
						Id:                    "tb1",
						Title:                 "Test Trust Boundary",
						TechnicalAssetsInside: []string{"ta1", "ta2"},
						Tags:                  []string{testCase.cloud},
						Type:                  types.NetworkCloudProvider,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)

			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Test Trust Boundary</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksTrustBoundaryWithoutCloudHardeningWithConfidentialTechnicalAssetRiskCreatedWithHighImpact(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws": {
			cloud:                 "aws",
			expectedTitleSuffix:   " (AWS)",
			expectedMessageSuffix: ": <u>CIS Benchmark for AWS</u>",
		},
		"azure": {
			cloud:                 "azure",
			expectedTitleSuffix:   " (Azure)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Microsoft Azure</u>",
		},
		"gcp": {
			cloud:                 "gcp",
			expectedTitleSuffix:   " (GCP)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Google Cloud Computing Platform</u>",
		},
		"ocp": {
			cloud:                 "ocp",
			expectedTitleSuffix:   " (OCP)",
			expectedMessageSuffix: ": <u>Vendor Best Practices for Oracle Cloud Platform</u>",
		},
		"unspecific-cloud": {
			cloud: "unspecific-cloud",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:              "ta1",
						Title:           "First Technical Asset Inside Trust Boundary",
						Tags:            []string{testCase.cloud},
						Confidentiality: types.Confidential,
					},
					"ta2": {
						Id:    "ta2",
						Title: "Second Technical Asset Inside Trust Boundary",
						Tags:  []string{testCase.cloud},
					},
					"ta3": {
						Id:    "ta3",
						Title: "Technical Asset Outside Trust Boundary",
						Tags:  []string{testCase.cloud},
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"tb1": {
						Id:                    "tb1",
						Title:                 "Test Trust Boundary",
						TechnicalAssetsInside: []string{"ta1", "ta2"},
						Tags:                  []string{testCase.cloud},
						Type:                  types.NetworkCloudProvider,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)

			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Test Trust Boundary</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksTrustBoundaryWithoutCloudHardeningWithStrictlyConfidentialTechnicalAssetRiskCreatedWithVeryHighImpact(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws": {
			cloud:                 "aws",
			expectedTitleSuffix:   " (AWS)",
			expectedMessageSuffix: ": <u>CIS Benchmark for AWS</u>",
		},
		"azure": {
			cloud:                 "azure",
			expectedTitleSuffix:   " (Azure)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Microsoft Azure</u>",
		},
		"gcp": {
			cloud:                 "gcp",
			expectedTitleSuffix:   " (GCP)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Google Cloud Computing Platform</u>",
		},
		"ocp": {
			cloud:                 "ocp",
			expectedTitleSuffix:   " (OCP)",
			expectedMessageSuffix: ": <u>Vendor Best Practices for Oracle Cloud Platform</u>",
		},
		"unspecific-cloud": {
			cloud: "unspecific-cloud",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:              "ta1",
						Title:           "First Technical Asset Inside Trust Boundary",
						Tags:            []string{testCase.cloud},
						Confidentiality: types.StrictlyConfidential,
					},
					"ta2": {
						Id:    "ta2",
						Title: "Second Technical Asset Inside Trust Boundary",
						Tags:  []string{testCase.cloud},
					},
					"ta3": {
						Id:    "ta3",
						Title: "Technical Asset Outside Trust Boundary",
						Tags:  []string{testCase.cloud},
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"tb1": {
						Id:                    "tb1",
						Title:                 "Test Trust Boundary",
						TechnicalAssetsInside: []string{"ta1", "ta2"},
						Tags:                  []string{testCase.cloud},
						Type:                  types.NetworkCloudProvider,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, types.VeryHighImpact, risks[0].ExploitationImpact)

			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Test Trust Boundary</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksSharedRuntimeWithoutCloudHardeningRiskCreated(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws": {
			cloud:                 "aws",
			expectedTitleSuffix:   " (AWS)",
			expectedMessageSuffix: ": <u>CIS Benchmark for AWS</u>",
		},
		"azure": {
			cloud:                 "azure",
			expectedTitleSuffix:   " (Azure)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Microsoft Azure</u>",
		},
		"gcp": {
			cloud:                 "gcp",
			expectedTitleSuffix:   " (GCP)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Google Cloud Computing Platform</u>",
		},
		"ocp": {
			cloud:                 "ocp",
			expectedTitleSuffix:   " (OCP)",
			expectedMessageSuffix: ": <u>Vendor Best Practices for Oracle Cloud Platform</u>",
		},
		"unspecific-cloud": {
			cloud: "unspecific-cloud",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "First Technical Asset Inside Shared Runtime",
						Tags:  []string{testCase.cloud},
					},
					"ta2": {
						Id:    "ta2",
						Title: "Second Technical Asset Inside Shared Runtime",
						Tags:  []string{testCase.cloud},
					},
					"ta3": {
						Id:    "ta3",
						Title: "Technical Asset Outside Shared Runtime",
					},
				},
				SharedRuntimes: map[string]*types.SharedRuntime{
					"tb1": {
						Id:                     "tb1",
						Title:                  "Test Shared Runtime",
						TechnicalAssetsRunning: []string{"ta1", "ta2"},
						Tags:                   []string{testCase.cloud},
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)

			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Test Shared Runtime</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksSharedRuntimeWithoutCloudHardeningWithCriticallyAvailableTechnicalAssetRiskCreatedWithHighImpact(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws": {
			cloud:                 "aws",
			expectedTitleSuffix:   " (AWS)",
			expectedMessageSuffix: ": <u>CIS Benchmark for AWS</u>",
		},
		"azure": {
			cloud:                 "azure",
			expectedTitleSuffix:   " (Azure)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Microsoft Azure</u>",
		},
		"gcp": {
			cloud:                 "gcp",
			expectedTitleSuffix:   " (GCP)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Google Cloud Computing Platform</u>",
		},
		"ocp": {
			cloud:                 "ocp",
			expectedTitleSuffix:   " (OCP)",
			expectedMessageSuffix: ": <u>Vendor Best Practices for Oracle Cloud Platform</u>",
		},
		"unspecific-cloud": {
			cloud: "unspecific-cloud",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:           "ta1",
						Title:        "First Technical Asset Inside Shared Runtime",
						Tags:         []string{testCase.cloud},
						Availability: types.Critical,
					},
					"ta2": {
						Id:    "ta2",
						Title: "Second Technical Asset Inside Shared Runtime",
						Tags:  []string{testCase.cloud},
					},
					"ta3": {
						Id:    "ta3",
						Title: "Technical Asset Outside Shared Runtime",
					},
				},
				SharedRuntimes: map[string]*types.SharedRuntime{
					"tb1": {
						Id:                     "tb1",
						Title:                  "Test Shared Runtime",
						TechnicalAssetsRunning: []string{"ta1", "ta2"},
						Tags:                   []string{testCase.cloud},
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)

			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Test Shared Runtime</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksSharedRuntimeWithoutCloudHardeningWithMissionCriticalAvailableTechnicalAssetRiskCreatedWithVeryHighImpact(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws": {
			cloud:                 "aws",
			expectedTitleSuffix:   " (AWS)",
			expectedMessageSuffix: ": <u>CIS Benchmark for AWS</u>",
		},
		"azure": {
			cloud:                 "azure",
			expectedTitleSuffix:   " (Azure)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Microsoft Azure</u>",
		},
		"gcp": {
			cloud:                 "gcp",
			expectedTitleSuffix:   " (GCP)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Google Cloud Computing Platform</u>",
		},
		"ocp": {
			cloud:                 "ocp",
			expectedTitleSuffix:   " (OCP)",
			expectedMessageSuffix: ": <u>Vendor Best Practices for Oracle Cloud Platform</u>",
		},
		"unspecific-cloud": {
			cloud: "unspecific-cloud",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:           "ta1",
						Title:        "First Technical Asset Inside Shared Runtime",
						Tags:         []string{testCase.cloud},
						Availability: types.MissionCritical,
					},
					"ta2": {
						Id:    "ta2",
						Title: "Second Technical Asset Inside Shared Runtime",
						Tags:  []string{testCase.cloud},
					},
					"ta3": {
						Id:    "ta3",
						Title: "Technical Asset Outside Shared Runtime",
					},
				},
				SharedRuntimes: map[string]*types.SharedRuntime{
					"tb1": {
						Id:                     "tb1",
						Title:                  "Test Shared Runtime",
						TechnicalAssetsRunning: []string{"ta1", "ta2"},
						Tags:                   []string{testCase.cloud},
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, types.VeryHighImpact, risks[0].ExploitationImpact)

			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Test Shared Runtime</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksTechnicalAssetWithoutCloudHardeningRiskCreated(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws": {
			cloud:                 "aws",
			expectedTitleSuffix:   " (AWS)",
			expectedMessageSuffix: ": <u>CIS Benchmark for AWS</u>",
		},
		"azure": {
			cloud:                 "azure",
			expectedTitleSuffix:   " (Azure)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Microsoft Azure</u>",
		},
		"gcp": {
			cloud:                 "gcp",
			expectedTitleSuffix:   " (GCP)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Google Cloud Computing Platform</u>",
		},
		"ocp": {
			cloud:                 "ocp",
			expectedTitleSuffix:   " (OCP)",
			expectedMessageSuffix: ": <u>Vendor Best Practices for Oracle Cloud Platform</u>",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "Technical Asset Without Cloud Hardening",
						Tags:  []string{testCase.cloud},
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)

			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Technical Asset Without Cloud Hardening</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksTechnicalAssetWithoutCloudHardeningProcessingCriticallyAvailableDataRiskCreatedWithHighImpact(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws": {
			cloud:                 "aws",
			expectedTitleSuffix:   " (AWS)",
			expectedMessageSuffix: ": <u>CIS Benchmark for AWS</u>",
		},
		"azure": {
			cloud:                 "azure",
			expectedTitleSuffix:   " (Azure)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Microsoft Azure</u>",
		},
		"gcp": {
			cloud:                 "gcp",
			expectedTitleSuffix:   " (GCP)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Google Cloud Computing Platform</u>",
		},
		"ocp": {
			cloud:                 "ocp",
			expectedTitleSuffix:   " (OCP)",
			expectedMessageSuffix: ": <u>Vendor Best Practices for Oracle Cloud Platform</u>",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:                  "ta1",
						Title:               "Technical Asset Without Cloud Hardening",
						Tags:                []string{testCase.cloud},
						DataAssetsProcessed: []string{"da1"},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"da1": {
						Id:           "da1",
						Title:        "Data Asset",
						Availability: types.Critical,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)

			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Technical Asset Without Cloud Hardening</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksTechnicalAssetWithoutCloudHardeningProcessingMissionCriticallyAvailableDataRiskCreatedWithVeryHighImpact(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws": {
			cloud:                 "aws",
			expectedTitleSuffix:   " (AWS)",
			expectedMessageSuffix: ": <u>CIS Benchmark for AWS</u>",
		},
		"azure": {
			cloud:                 "azure",
			expectedTitleSuffix:   " (Azure)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Microsoft Azure</u>",
		},
		"gcp": {
			cloud:                 "gcp",
			expectedTitleSuffix:   " (GCP)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Google Cloud Computing Platform</u>",
		},
		"ocp": {
			cloud:                 "ocp",
			expectedTitleSuffix:   " (OCP)",
			expectedMessageSuffix: ": <u>Vendor Best Practices for Oracle Cloud Platform</u>",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:                  "ta1",
						Title:               "Technical Asset Without Cloud Hardening",
						Tags:                []string{testCase.cloud},
						DataAssetsProcessed: []string{"da1"},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"da1": {
						Id:           "da1",
						Title:        "Data Asset",
						Availability: types.MissionCritical,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, types.VeryHighImpact, risks[0].ExploitationImpact)

			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Technical Asset Without Cloud Hardening</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksTechnicalAssetSpecificWithoutCloudHardeningRiskCreated(t *testing.T) {
	testCases := map[string]CloudHardeningRuleTest{
		"aws:ec2": {
			cloud:                 "aws:ec2",
			expectedTitleSuffix:   " (EC2)",
			expectedMessageSuffix: ": <u>CIS Benchmark for Amazon Linux</u>",
		},
		"aws:s3": {
			cloud:                 "aws:s3",
			expectedTitleSuffix:   " (S3)",
			expectedMessageSuffix: ": <u>Security Best Practices for AWS S3</u>",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingCloudHardeningRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "Technical Asset Without Cloud Hardening",
						Tags:  []string{testCase.cloud},
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 2)
			assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Missing Cloud Hardening (AWS)</b> risk at <b>Technical Asset Without Cloud Hardening</b>: <u>CIS Benchmark for AWS</u>", risks[0].Title)

			assert.Equal(t, types.MediumImpact, risks[1].ExploitationImpact)
			expTitle := fmt.Sprintf("<b>Missing Cloud Hardening%s</b> risk at <b>Technical Asset Without Cloud Hardening</b>%s", testCase.expectedTitleSuffix, testCase.expectedMessageSuffix)
			assert.Equal(t, expTitle, risks[1].Title)
		})
	}
}

func TestMissingCloudHardeningRuleGenerateRisksSpecificTagsCloudHardeningRiskCreated(t *testing.T) {
	rule := NewMissingCloudHardeningRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "First Technical Asset Inside Trust Boundary",
				Tags:  []string{"aws:lambda"},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Second Technical Asset Inside Trust Boundary",
			},
			"ta3": {
				Id:    "ta3",
				Title: "Technical Asset Outside Trust Boundary",
			},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id:                    "tb1",
				Title:                 "Test Trust Boundary",
				TechnicalAssetsInside: []string{"ta1", "ta2"},
				Tags:                  []string{"aws:vpc"},
				Type:                  types.NetworkCloudProvider,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Cloud Hardening (AWS)</b> risk at <b>Test Trust Boundary</b>: <u>CIS Benchmark for AWS</u>", risks[0].Title)
}
