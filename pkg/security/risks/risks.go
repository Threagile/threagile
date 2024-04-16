package risks

import (
	"embed"
	"fmt"
	"github.com/threagile/threagile/pkg/script"
	"github.com/threagile/threagile/pkg/security/risks/builtin"
	"github.com/threagile/threagile/pkg/security/types"
	"io/fs"
)

func GetBuiltInRiskRules() types.RiskRules {
	rules := make(types.RiskRules)
	for _, rule := range []types.RiskRule{
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
	} {
		rules[rule.Category().ID] = rule
	}

	scriptRules, scriptError := GetScriptRiskRules()
	if scriptError != nil {
		fmt.Printf("error loading script risk rules: %v\n", scriptError)
		return rules
	}

	for id, rule := range scriptRules {
		builtinRule, ok := rules[id]
		if ok && builtinRule != nil {
			fmt.Printf("WARNING: script risk rule %q shadows built-in risk rule\n", id)
		}

		rules[id] = rule
	}

	return rules
}

//go:embed scripts/*.yaml
var ruleScripts embed.FS

type RiskRules types.RiskRules

func GetScriptRiskRules() (RiskRules, error) {
	return make(RiskRules).LoadRiskRules()
}

func (what RiskRules) LoadRiskRules() (RiskRules, error) {
	fileSystem := ruleScripts
	walkError := fs.WalkDir(fileSystem, "scripts", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		newRule := new(script.RiskRule).Init()
		loadError := newRule.Load(fileSystem, path, entry)
		if loadError != nil {
			return loadError
		}

		if newRule.Category().ID == "" {
			return nil
		}

		what[newRule.Category().ID] = newRule
		return nil
	})

	if walkError != nil {
		return nil, walkError
	}

	return what, nil
}
