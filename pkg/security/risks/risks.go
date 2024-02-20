package risks

import (
	"github.com/threagile/threagile/pkg/security/risks/builtin"
)

func GetBuiltInRiskRules() []RiskRule {
	return []RiskRule{
		builtin.NewAccidentalSecretLeakRule(),
		builtin.NewCodeBackdooringRule(),
		builtin.NewContainerBaseImageBackdooringRule(),
		builtin.NewContainerPlatformEscapeRule(),
		builtin.NewCrossSiteRequestForgeryRule(),
		builtin.NewCrossSiteScriptingRule(),
		builtin.NewDosRiskyAccessAcrossTrustBoundaryRule(),
		builtin.NewIncompleteModelRule(),
		builtin.NewLdapInjectionRule(),
		builtin.NewMissingAuthenticationRule(),
		builtin.NewMissingAuthenticationSecondFactorRule(builtin.NewMissingAuthenticationRule()),
		builtin.NewMissingBuildInfrastructureRule(),
		builtin.NewMissingCloudHardeningRule(),
		builtin.NewMissingFileValidationRule(),
		builtin.NewMissingHardeningRule(),
		builtin.NewMissingIdentityPropagationRule(),
		builtin.NewMissingIdentityProviderIsolationRule(),
		builtin.NewMissingIdentityStoreRule(),
		builtin.NewMissingNetworkSegmentationRule(),
		builtin.NewMissingVaultRule(),
		builtin.NewMissingVaultIsolationRule(),
		builtin.NewMissingWafRule(),
		builtin.NewMixedTargetsOnSharedRuntimeRule(),
		builtin.NewPathTraversalRule(),
		builtin.NewPushInsteadPullDeploymentRule(),
		builtin.NewSearchQueryInjectionRule(),
		builtin.NewServerSideRequestForgeryRule(),
		builtin.NewServiceRegistryPoisoningRule(),
		builtin.NewSqlNoSqlInjectionRule(),
		builtin.NewUncheckedDeploymentRule(),
		builtin.NewUnencryptedAssetRule(),
		builtin.NewUnencryptedCommunicationRule(),
		builtin.NewUnguardedAccessFromInternetRule(),
		builtin.NewUnguardedDirectDatastoreAccessRule(),
		builtin.NewUnnecessaryCommunicationLinkRule(),
		builtin.NewUnnecessaryDataAssetRule(),
		builtin.NewUnnecessaryDataTransferRule(),
		builtin.NewUnnecessaryTechnicalAssetRule(),
		builtin.NewUntrustedDeserializationRule(),
		builtin.NewWrongCommunicationLinkContentRule(),
		builtin.NewWrongTrustBoundaryContentRule(),
		builtin.NewXmlExternalEntityRule(),
	}
}
