package risks

import (
	accidentalsecretleak "github.com/threagile/threagile/pkg/security/risks/built-in/accidental-secret-leak"
	codebackdooring "github.com/threagile/threagile/pkg/security/risks/built-in/code-backdooring"
	containerbaseimagebackdooring "github.com/threagile/threagile/pkg/security/risks/built-in/container-baseimage-backdooring"
	containerplatformescape "github.com/threagile/threagile/pkg/security/risks/built-in/container-platform-escape"
	crosssiterequestforgery "github.com/threagile/threagile/pkg/security/risks/built-in/cross-site-request-forgery"
	crosssitescripting "github.com/threagile/threagile/pkg/security/risks/built-in/cross-site-scripting"
	dosriskyaccessacrosstrustboundary "github.com/threagile/threagile/pkg/security/risks/built-in/dos-risky-access-across-trust-boundary"
	incompletemodel "github.com/threagile/threagile/pkg/security/risks/built-in/incomplete-model"
	ldapinjection "github.com/threagile/threagile/pkg/security/risks/built-in/ldap-injection"
	missingauthentication "github.com/threagile/threagile/pkg/security/risks/built-in/missing-authentication"
	missingauthenticationsecondfactor "github.com/threagile/threagile/pkg/security/risks/built-in/missing-authentication-second-factor"
	missingbuildinfrastructure "github.com/threagile/threagile/pkg/security/risks/built-in/missing-build-infrastructure"
	missingcloudhardening "github.com/threagile/threagile/pkg/security/risks/built-in/missing-cloud-hardening"
	missingfilevalidation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-file-validation"
	missinghardening "github.com/threagile/threagile/pkg/security/risks/built-in/missing-hardening"
	missingidentitypropagation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-identity-propagation"
	missingidentityproviderisolation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-identity-provider-isolation"
	missingidentitystore "github.com/threagile/threagile/pkg/security/risks/built-in/missing-identity-store"
	missingnetworksegmentation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-network-segmentation"
	missingvault "github.com/threagile/threagile/pkg/security/risks/built-in/missing-vault"
	missingvaultisolation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-vault-isolation"
	missingwaf "github.com/threagile/threagile/pkg/security/risks/built-in/missing-waf"
	mixedtargetsonsharedruntime "github.com/threagile/threagile/pkg/security/risks/built-in/mixed-targets-on-shared-runtime"
	pathtraversal "github.com/threagile/threagile/pkg/security/risks/built-in/path-traversal"
	pushinsteadofpulldeployment "github.com/threagile/threagile/pkg/security/risks/built-in/push-instead-of-pull-deployment"
	searchqueryinjection "github.com/threagile/threagile/pkg/security/risks/built-in/search-query-injection"
	serversiderequestforgery "github.com/threagile/threagile/pkg/security/risks/built-in/server-side-request-forgery"
	serviceregistrypoisoning "github.com/threagile/threagile/pkg/security/risks/built-in/service-registry-poisoning"
	sqlnosqlinjection "github.com/threagile/threagile/pkg/security/risks/built-in/sql-nosql-injection"
	uncheckeddeployment "github.com/threagile/threagile/pkg/security/risks/built-in/unchecked-deployment"
	unencryptedasset "github.com/threagile/threagile/pkg/security/risks/built-in/unencrypted-asset"
	unencryptedcommunication "github.com/threagile/threagile/pkg/security/risks/built-in/unencrypted-communication"
	unguardedaccessfrominternet "github.com/threagile/threagile/pkg/security/risks/built-in/unguarded-access-from-internet"
	unguardeddirectdatastoreaccess "github.com/threagile/threagile/pkg/security/risks/built-in/unguarded-direct-datastore-access"
	unnecessarycommunicationlink "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-communication-link"
	unnecessarydataasset "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-data-asset"
	unnecessarydatatransfer "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-data-transfer"
	unnecessarytechnicalasset "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-technical-asset"
	untrusteddeserialization "github.com/threagile/threagile/pkg/security/risks/built-in/untrusted-deserialization"
	wrongcommunicationlinkcontent "github.com/threagile/threagile/pkg/security/risks/built-in/wrong-communication-link-content"
	wrongtrustboundarycontent "github.com/threagile/threagile/pkg/security/risks/built-in/wrong-trust-boundary-content"
	xmlexternalentity "github.com/threagile/threagile/pkg/security/risks/built-in/xml-external-entity"
	"github.com/threagile/threagile/pkg/security/types"
)

func GetBuiltInRiskRules() []types.RiskRule {
	return []types.RiskRule{
		accidentalsecretleak.Rule(),
		codebackdooring.Rule(),
		containerbaseimagebackdooring.Rule(),
		containerplatformescape.Rule(),
		crosssiterequestforgery.Rule(),
		crosssitescripting.Rule(),
		dosriskyaccessacrosstrustboundary.Rule(),
		incompletemodel.Rule(),
		ldapinjection.Rule(),
		missingauthentication.Rule(),
		missingauthenticationsecondfactor.Rule(),
		missingbuildinfrastructure.Rule(),
		missingcloudhardening.Rule(),
		missingfilevalidation.Rule(),
		missinghardening.Rule(),
		missingidentitypropagation.Rule(),
		missingidentityproviderisolation.Rule(),
		missingidentitystore.Rule(),
		missingnetworksegmentation.Rule(),
		missingvault.Rule(),
		missingvaultisolation.Rule(),
		missingwaf.Rule(),
		mixedtargetsonsharedruntime.Rule(),
		pathtraversal.Rule(),
		pushinsteadofpulldeployment.Rule(),
		searchqueryinjection.Rule(),
		serversiderequestforgery.Rule(),
		serviceregistrypoisoning.Rule(),
		sqlnosqlinjection.Rule(),
		uncheckeddeployment.Rule(),
		unencryptedasset.Rule(),
		unencryptedcommunication.Rule(),
		unguardedaccessfrominternet.Rule(),
		unguardeddirectdatastoreaccess.Rule(),
		unnecessarycommunicationlink.Rule(),
		unnecessarydataasset.Rule(),
		unnecessarydatatransfer.Rule(),
		unnecessarytechnicalasset.Rule(),
		untrusteddeserialization.Rule(),
		wrongcommunicationlinkcontent.Rule(),
		wrongtrustboundarycontent.Rule(),
		xmlexternalentity.Rule(),
	}
}
