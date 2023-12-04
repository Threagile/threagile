package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"plugin"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/threagile/threagile/colors"
	addbuildpipeline "github.com/threagile/threagile/macros/built-in/add-build-pipeline"
	addvault "github.com/threagile/threagile/macros/built-in/add-vault"
	prettyprint "github.com/threagile/threagile/macros/built-in/pretty-print"
	removeunusedtags "github.com/threagile/threagile/macros/built-in/remove-unused-tags"
	seedrisktracking "github.com/threagile/threagile/macros/built-in/seed-risk-tracking"
	seedtags "github.com/threagile/threagile/macros/built-in/seed-tags"
	"github.com/threagile/threagile/model"
	"github.com/threagile/threagile/report"
	accidentalsecretleak "github.com/threagile/threagile/risks/built-in/accidental-secret-leak"
	codebackdooring "github.com/threagile/threagile/risks/built-in/code-backdooring"
	containerbaseimagebackdooring "github.com/threagile/threagile/risks/built-in/container-baseimage-backdooring"
	containerplatformescape "github.com/threagile/threagile/risks/built-in/container-platform-escape"
	crosssiterequestforgery "github.com/threagile/threagile/risks/built-in/cross-site-request-forgery"
	crosssitescripting "github.com/threagile/threagile/risks/built-in/cross-site-scripting"
	dosriskyaccessacrosstrustboundary "github.com/threagile/threagile/risks/built-in/dos-risky-access-across-trust-boundary"
	incompletemodel "github.com/threagile/threagile/risks/built-in/incomplete-model"
	ldapinjection "github.com/threagile/threagile/risks/built-in/ldap-injection"
	missingauthentication "github.com/threagile/threagile/risks/built-in/missing-authentication"
	missingauthenticationsecondfactor "github.com/threagile/threagile/risks/built-in/missing-authentication-second-factor"
	missingbuildinfrastructure "github.com/threagile/threagile/risks/built-in/missing-build-infrastructure"
	missingcloudhardening "github.com/threagile/threagile/risks/built-in/missing-cloud-hardening"
	missingfilevalidation "github.com/threagile/threagile/risks/built-in/missing-file-validation"
	missinghardening "github.com/threagile/threagile/risks/built-in/missing-hardening"
	missingidentitypropagation "github.com/threagile/threagile/risks/built-in/missing-identity-propagation"
	missingidentityproviderisolation "github.com/threagile/threagile/risks/built-in/missing-identity-provider-isolation"
	missingidentitystore "github.com/threagile/threagile/risks/built-in/missing-identity-store"
	missingnetworksegmentation "github.com/threagile/threagile/risks/built-in/missing-network-segmentation"
	missingvault "github.com/threagile/threagile/risks/built-in/missing-vault"
	missingvaultisolation "github.com/threagile/threagile/risks/built-in/missing-vault-isolation"
	missingwaf "github.com/threagile/threagile/risks/built-in/missing-waf"
	mixedtargetsonsharedruntime "github.com/threagile/threagile/risks/built-in/mixed-targets-on-shared-runtime"
	pathtraversal "github.com/threagile/threagile/risks/built-in/path-traversal"
	pushinsteadofpulldeployment "github.com/threagile/threagile/risks/built-in/push-instead-of-pull-deployment"
	searchqueryinjection "github.com/threagile/threagile/risks/built-in/search-query-injection"
	serversiderequestforgery "github.com/threagile/threagile/risks/built-in/server-side-request-forgery"
	serviceregistrypoisoning "github.com/threagile/threagile/risks/built-in/service-registry-poisoning"
	sqlnosqlinjection "github.com/threagile/threagile/risks/built-in/sql-nosql-injection"
	uncheckeddeployment "github.com/threagile/threagile/risks/built-in/unchecked-deployment"
	unencryptedasset "github.com/threagile/threagile/risks/built-in/unencrypted-asset"
	unencryptedcommunication "github.com/threagile/threagile/risks/built-in/unencrypted-communication"
	unguardedaccessfrominternet "github.com/threagile/threagile/risks/built-in/unguarded-access-from-internet"
	unguardeddirectdatastoreaccess "github.com/threagile/threagile/risks/built-in/unguarded-direct-datastore-access"
	unnecessarycommunicationlink "github.com/threagile/threagile/risks/built-in/unnecessary-communication-link"
	unnecessarydataasset "github.com/threagile/threagile/risks/built-in/unnecessary-data-asset"
	unnecessarydatatransfer "github.com/threagile/threagile/risks/built-in/unnecessary-data-transfer"
	unnecessarytechnicalasset "github.com/threagile/threagile/risks/built-in/unnecessary-technical-asset"
	untrusteddeserialization "github.com/threagile/threagile/risks/built-in/untrusted-deserialization"
	wrongcommunicationlinkcontent "github.com/threagile/threagile/risks/built-in/wrong-communication-link-content"
	wrongtrustboundarycontent "github.com/threagile/threagile/risks/built-in/wrong-trust-boundary-content"
	xmlexternalentity "github.com/threagile/threagile/risks/built-in/xml-external-entity"
	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

const keepDiagramSourceFiles = false
const defaultGraphvizDPI, maxGraphvizDPI = 120, 240

const backupHistoryFilesToKeep = 50

const baseFolder, reportFilename, excelRisksFilename, excelTagsFilename, jsonRisksFilename, jsonTechnicalAssetsFilename, jsonStatsFilename, dataFlowDiagramFilenameDOT, dataFlowDiagramFilenamePNG, dataAssetDiagramFilenameDOT, dataAssetDiagramFilenamePNG, graphvizDataFlowDiagramConversionCall, graphvizDataAssetDiagramConversionCall = "/data", "report.pdf", "risks.xlsx", "tags.xlsx", "risks.json", "technical-assets.json", "stats.json", "data-flow-diagram.gv", "data-flow-diagram.png", "data-asset-diagram.gv", "data-asset-diagram.png", "render-data-flow-diagram.sh", "render-data-asset-diagram.sh"

var globalLock sync.Mutex
var successCount, errorCount = 0, 0

var modelInput model.ModelInput

var drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = true

var buildTimestamp = ""

var modelFilename, templateFilename /*, diagramFilename, reportFilename, graphvizConversion*/ *string
var createExampleModel, createStubModel, createEditingSupport, verbose, ignoreOrphanedRiskTracking, generateDataFlowDiagram, generateDataAssetDiagram, generateRisksJSON, generateTechnicalAssetsJSON, generateStatsJSON, generateRisksExcel, generateTagsExcel, generateReportPDF *bool
var outputDir, raaPlugin, skipRiskRules, riskRulesPlugins, executeModelMacro *string
var customRiskRules map[string]model.CustomRiskRule
var diagramDPI, serverPort *int

var deferredRiskTrackingDueToWildcardMatching = make(map[string]model.RiskTracking)

func applyRiskGeneration() {
	if *verbose {
		fmt.Println("Applying risk generation")
	}
	skippedRules := make(map[string]interface{})
	if len(*skipRiskRules) > 0 {
		for _, id := range strings.Split(*skipRiskRules, ",") {
			skippedRules[id] = true
		}
	}

	if _, ok := skippedRules[unencryptedasset.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unencryptedasset.Category().Id)
		delete(skippedRules, unencryptedasset.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unencryptedasset.SupportedTags())
		risks := unencryptedasset.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unencryptedasset.Category()] = risks
		}
	}

	if _, ok := skippedRules[unencryptedcommunication.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unencryptedcommunication.Category().Id)
		delete(skippedRules, unencryptedcommunication.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unencryptedcommunication.SupportedTags())
		risks := unencryptedcommunication.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unencryptedcommunication.Category()] = risks
		}
	}

	if _, ok := skippedRules[unguardeddirectdatastoreaccess.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unguardeddirectdatastoreaccess.Category().Id)
		delete(skippedRules, unguardeddirectdatastoreaccess.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unguardeddirectdatastoreaccess.SupportedTags())
		risks := unguardeddirectdatastoreaccess.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unguardeddirectdatastoreaccess.Category()] = risks
		}
	}

	if _, ok := skippedRules[unguardedaccessfrominternet.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unguardedaccessfrominternet.Category().Id)
		delete(skippedRules, unguardedaccessfrominternet.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unguardedaccessfrominternet.SupportedTags())
		risks := unguardedaccessfrominternet.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unguardedaccessfrominternet.Category()] = risks
		}
	}

	if _, ok := skippedRules[dosriskyaccessacrosstrustboundary.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", dosriskyaccessacrosstrustboundary.Category().Id)
		delete(skippedRules, dosriskyaccessacrosstrustboundary.Category().Id)
	} else {
		model.AddToListOfSupportedTags(dosriskyaccessacrosstrustboundary.SupportedTags())
		risks := dosriskyaccessacrosstrustboundary.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[dosriskyaccessacrosstrustboundary.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingnetworksegmentation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingnetworksegmentation.Category().Id)
		delete(skippedRules, missingnetworksegmentation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingnetworksegmentation.SupportedTags())
		risks := missingnetworksegmentation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingnetworksegmentation.Category()] = risks
		}
	}

	if _, ok := skippedRules[mixedtargetsonsharedruntime.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", mixedtargetsonsharedruntime.Category().Id)
		delete(skippedRules, mixedtargetsonsharedruntime.Category().Id)
	} else {
		model.AddToListOfSupportedTags(mixedtargetsonsharedruntime.SupportedTags())
		risks := mixedtargetsonsharedruntime.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[mixedtargetsonsharedruntime.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingidentitypropagation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingidentitypropagation.Category().Id)
		delete(skippedRules, missingidentitypropagation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingidentitypropagation.SupportedTags())
		risks := missingidentitypropagation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingidentitypropagation.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingidentitystore.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingidentitystore.Category().Id)
		delete(skippedRules, missingidentitystore.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingidentitystore.SupportedTags())
		risks := missingidentitystore.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingidentitystore.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingauthentication.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingauthentication.Category().Id)
		delete(skippedRules, missingauthentication.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingauthentication.SupportedTags())
		risks := missingauthentication.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingauthentication.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingauthenticationsecondfactor.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingauthenticationsecondfactor.Category().Id)
		delete(skippedRules, missingauthenticationsecondfactor.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingauthenticationsecondfactor.SupportedTags())
		risks := missingauthenticationsecondfactor.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingauthenticationsecondfactor.Category()] = risks
		}
	}

	if _, ok := skippedRules[unnecessarydatatransfer.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unnecessarydatatransfer.Category().Id)
		delete(skippedRules, unnecessarydatatransfer.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unnecessarydatatransfer.SupportedTags())
		risks := unnecessarydatatransfer.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unnecessarydatatransfer.Category()] = risks
		}
	}

	if _, ok := skippedRules[unnecessarycommunicationlink.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unnecessarycommunicationlink.Category().Id)
		delete(skippedRules, unnecessarycommunicationlink.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unnecessarycommunicationlink.SupportedTags())
		risks := unnecessarycommunicationlink.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unnecessarycommunicationlink.Category()] = risks
		}
	}

	if _, ok := skippedRules[unnecessarytechnicalasset.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unnecessarytechnicalasset.Category().Id)
		delete(skippedRules, unnecessarytechnicalasset.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unnecessarytechnicalasset.SupportedTags())
		risks := unnecessarytechnicalasset.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unnecessarytechnicalasset.Category()] = risks
		}
	}

	if _, ok := skippedRules[unnecessarydataasset.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unnecessarydataasset.Category().Id)
		delete(skippedRules, unnecessarydataasset.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unnecessarydataasset.SupportedTags())
		risks := unnecessarydataasset.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unnecessarydataasset.Category()] = risks
		}
	}

	if _, ok := skippedRules[sqlnosqlinjection.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", sqlnosqlinjection.Category().Id)
		delete(skippedRules, sqlnosqlinjection.Category().Id)
	} else {
		model.AddToListOfSupportedTags(sqlnosqlinjection.SupportedTags())
		risks := sqlnosqlinjection.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[sqlnosqlinjection.Category()] = risks
		}
	}

	if _, ok := skippedRules[ldapinjection.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", ldapinjection.Category().Id)
		delete(skippedRules, ldapinjection.Category().Id)
	} else {
		model.AddToListOfSupportedTags(ldapinjection.SupportedTags())
		risks := ldapinjection.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[ldapinjection.Category()] = risks
		}
	}

	if _, ok := skippedRules[crosssitescripting.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", crosssitescripting.Category().Id)
		delete(skippedRules, crosssitescripting.Category().Id)
	} else {
		model.AddToListOfSupportedTags(crosssitescripting.SupportedTags())
		risks := crosssitescripting.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[crosssitescripting.Category()] = risks
		}
	}

	if _, ok := skippedRules[crosssiterequestforgery.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", crosssiterequestforgery.Category().Id)
		delete(skippedRules, crosssiterequestforgery.Category().Id)
	} else {
		model.AddToListOfSupportedTags(crosssiterequestforgery.SupportedTags())
		risks := crosssiterequestforgery.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[crosssiterequestforgery.Category()] = risks
		}
	}

	if _, ok := skippedRules[serversiderequestforgery.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", serversiderequestforgery.Category().Id)
		delete(skippedRules, serversiderequestforgery.Category().Id)
	} else {
		model.AddToListOfSupportedTags(serversiderequestforgery.SupportedTags())
		risks := serversiderequestforgery.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[serversiderequestforgery.Category()] = risks
		}
	}

	if _, ok := skippedRules[pathtraversal.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", pathtraversal.Category().Id)
		delete(skippedRules, pathtraversal.Category().Id)
	} else {
		model.AddToListOfSupportedTags(pathtraversal.SupportedTags())
		risks := pathtraversal.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[pathtraversal.Category()] = risks
		}
	}

	if _, ok := skippedRules[pushinsteadofpulldeployment.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", pushinsteadofpulldeployment.Category().Id)
		delete(skippedRules, pushinsteadofpulldeployment.Category().Id)
	} else {
		model.AddToListOfSupportedTags(pushinsteadofpulldeployment.SupportedTags())
		risks := pushinsteadofpulldeployment.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[pushinsteadofpulldeployment.Category()] = risks
		}
	}

	if _, ok := skippedRules[searchqueryinjection.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", searchqueryinjection.Category().Id)
		delete(skippedRules, searchqueryinjection.Category().Id)
	} else {
		model.AddToListOfSupportedTags(searchqueryinjection.SupportedTags())
		risks := searchqueryinjection.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[searchqueryinjection.Category()] = risks
		}
	}

	if _, ok := skippedRules[serviceregistrypoisoning.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", serviceregistrypoisoning.Category().Id)
		delete(skippedRules, serviceregistrypoisoning.Category().Id)
	} else {
		model.AddToListOfSupportedTags(serviceregistrypoisoning.SupportedTags())
		risks := serviceregistrypoisoning.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[serviceregistrypoisoning.Category()] = risks
		}
	}

	if _, ok := skippedRules[untrusteddeserialization.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", untrusteddeserialization.Category().Id)
		delete(skippedRules, untrusteddeserialization.Category().Id)
	} else {
		model.AddToListOfSupportedTags(untrusteddeserialization.SupportedTags())
		risks := untrusteddeserialization.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[untrusteddeserialization.Category()] = risks
		}
	}

	if _, ok := skippedRules[xmlexternalentity.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", xmlexternalentity.Category().Id)
		delete(skippedRules, xmlexternalentity.Category().Id)
	} else {
		model.AddToListOfSupportedTags(xmlexternalentity.SupportedTags())
		risks := xmlexternalentity.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[xmlexternalentity.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingcloudhardening.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingcloudhardening.Category().Id)
		delete(skippedRules, missingcloudhardening.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingcloudhardening.SupportedTags())
		risks := missingcloudhardening.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingcloudhardening.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingfilevalidation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingfilevalidation.Category().Id)
		delete(skippedRules, missingfilevalidation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingfilevalidation.SupportedTags())
		risks := missingfilevalidation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingfilevalidation.Category()] = risks
		}
	}

	if _, ok := skippedRules[missinghardening.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missinghardening.Category().Id)
		delete(skippedRules, missinghardening.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missinghardening.SupportedTags())
		risks := missinghardening.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missinghardening.Category()] = risks
		}
	}

	if _, ok := skippedRules[accidentalsecretleak.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", accidentalsecretleak.Category().Id)
		delete(skippedRules, accidentalsecretleak.Category().Id)
	} else {
		model.AddToListOfSupportedTags(accidentalsecretleak.SupportedTags())
		risks := accidentalsecretleak.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[accidentalsecretleak.Category()] = risks
		}
	}

	if _, ok := skippedRules[codebackdooring.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", codebackdooring.Category().Id)
		delete(skippedRules, codebackdooring.Category().Id)
	} else {
		model.AddToListOfSupportedTags(codebackdooring.SupportedTags())
		risks := codebackdooring.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[codebackdooring.Category()] = risks
		}
	}

	if _, ok := skippedRules[containerbaseimagebackdooring.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", containerbaseimagebackdooring.Category().Id)
		delete(skippedRules, containerbaseimagebackdooring.Category().Id)
	} else {
		model.AddToListOfSupportedTags(containerbaseimagebackdooring.SupportedTags())
		risks := containerbaseimagebackdooring.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[containerbaseimagebackdooring.Category()] = risks
		}
	}

	if _, ok := skippedRules[containerplatformescape.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", containerplatformescape.Category().Id)
		delete(skippedRules, containerplatformescape.Category().Id)
	} else {
		model.AddToListOfSupportedTags(containerplatformescape.SupportedTags())
		risks := containerplatformescape.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[containerplatformescape.Category()] = risks
		}
	}

	if _, ok := skippedRules[incompletemodel.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", incompletemodel.Category().Id)
		delete(skippedRules, incompletemodel.Category().Id)
	} else {
		model.AddToListOfSupportedTags(incompletemodel.SupportedTags())
		risks := incompletemodel.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[incompletemodel.Category()] = risks
		}
	}

	if _, ok := skippedRules[uncheckeddeployment.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", uncheckeddeployment.Category().Id)
		delete(skippedRules, uncheckeddeployment.Category().Id)
	} else {
		model.AddToListOfSupportedTags(uncheckeddeployment.SupportedTags())
		risks := uncheckeddeployment.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[uncheckeddeployment.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingbuildinfrastructure.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingbuildinfrastructure.Category().Id)
		delete(skippedRules, missingbuildinfrastructure.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingbuildinfrastructure.SupportedTags())
		risks := missingbuildinfrastructure.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingbuildinfrastructure.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingidentityproviderisolation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingidentityproviderisolation.Category().Id)
		delete(skippedRules, missingidentityproviderisolation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingidentityproviderisolation.SupportedTags())
		risks := missingidentityproviderisolation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingidentityproviderisolation.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingvault.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingvault.Category().Id)
		delete(skippedRules, missingvault.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingvault.SupportedTags())
		risks := missingvault.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingvault.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingvaultisolation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingvaultisolation.Category().Id)
		delete(skippedRules, missingvaultisolation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingvaultisolation.SupportedTags())
		risks := missingvaultisolation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingvaultisolation.Category()] = risks
		}
	}

	if _, ok := skippedRules[missingwaf.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missingwaf.Category().Id)
		delete(skippedRules, missingwaf.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missingwaf.SupportedTags())
		risks := missingwaf.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missingwaf.Category()] = risks
		}
	}

	if _, ok := skippedRules[wrongcommunicationlinkcontent.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", wrongcommunicationlinkcontent.Category().Id)
		delete(skippedRules, wrongcommunicationlinkcontent.Category().Id)
	} else {
		model.AddToListOfSupportedTags(wrongcommunicationlinkcontent.SupportedTags())
		risks := wrongcommunicationlinkcontent.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[wrongcommunicationlinkcontent.Category()] = risks
		}
	}

	if _, ok := skippedRules[wrongtrustboundarycontent.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", wrongtrustboundarycontent.Category().Id)
		delete(skippedRules, wrongtrustboundarycontent.Category().Id)
	} else {
		model.AddToListOfSupportedTags(wrongtrustboundarycontent.SupportedTags())
		risks := wrongtrustboundarycontent.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[wrongtrustboundarycontent.Category()] = risks
		}
	}

	// NOW THE CUSTOM RISK RULES (if any)
	for id, customRule := range customRiskRules {
		if _, ok := skippedRules[customRule.Category().Id]; ok {
			if *verbose {
				fmt.Println("Skipping custom risk rule:", id)
			}
			delete(skippedRules, id)
		} else {
			if *verbose {
				fmt.Println("Executing custom risk rule:", id)
			}
			model.AddToListOfSupportedTags(customRule.SupportedTags())
			risks := customRule.GenerateRisks()
			if len(risks) > 0 {
				model.GeneratedRisksByCategory[customRule.Category()] = risks
			}
			if *verbose {
				fmt.Println("Added custom risks:", len(risks))
			}
		}
	}

	if len(skippedRules) > 0 {
		keys := make([]string, 0)
		for k := range skippedRules {
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			log.Println("Unknown risk rules to skip:", keys)
		}
	}

	// save also in map keyed by synthetic risk-id
	for _, category := range model.SortedRiskCategories() {
		risks := model.SortedRisksOfCategory(category)
		for _, risk := range risks {
			model.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}
}

func checkRiskTracking() {
	if *verbose {
		fmt.Println("Checking risk tracking")
	}
	for _, tracking := range model.ParsedModelRoot.RiskTracking {
		if _, ok := model.GeneratedRisksBySyntheticId[tracking.SyntheticRiskId]; !ok {
			if *ignoreOrphanedRiskTracking {
				fmt.Println("Risk tracking references unknown risk (risk id not found): " + tracking.SyntheticRiskId)
			} else {
				panic(errors.New("Risk tracking references unknown risk (risk id not found) - you might want to use the option -ignore-orphaned-risk-tracking: " + tracking.SyntheticRiskId +
					"\n\nNOTE: For risk tracking each risk-id needs to be defined (the string with the @ sign in it). " +
					"These unique risk IDs are visible in the PDF report (the small grey string under each risk), " +
					"the Excel (column \"ID\"), as well as the JSON responses. Some risk IDs have only one @ sign in them, " +
					"while others multiple. The idea is to allow for unique but still speaking IDs. Therefore each risk instance " +
					"creates its individual ID by taking all affected elements causing the risk to be within an @-delimited part. " +
					"Using wildcards (the * sign) for parts delimited by @ signs allows to handle groups of certain risks at once. " +
					"Best is to lookup the IDs to use in the created Excel file. Alternatively a model macro \"seed-risk-tracking\" " +
					"is available that helps in initially seeding the risk tracking part here based on already identified and not yet handled risks."))
			}
		}
	}

	// save also the risk-category-id and risk-status directly in the risk for better JSON marshalling
	for category := range model.GeneratedRisksByCategory {
		for i := range model.GeneratedRisksByCategory[category] {
			model.GeneratedRisksByCategory[category][i].CategoryId = category.Id
			model.GeneratedRisksByCategory[category][i].RiskStatus = model.GeneratedRisksByCategory[category][i].GetRiskTrackingStatusDefaultingUnchecked()
		}
	}
}

// === Error handling stuff ========================================

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	parseCommandlineArgs()
	if *serverPort > 0 {
		startServer()
	} else {
		doIt(*modelFilename, *outputDir)
	}
}

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func unzip(src string, dest string) ([]string, error) {
	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		// Store filename/path for returning and using later on
		path := filepath.Join(dest, f.Name)
		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", path)
		}
		filenames = append(filenames, path)
		if f.FileInfo().IsDir() {
			// Make Folder
			_ = os.MkdirAll(path, os.ModePerm)
			continue
		}
		// Make File
		if err = os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
			return filenames, err
		}
		outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}
		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		_, err = io.Copy(outFile, rc)
		// Close the file without defer to close before next iteration of loop
		_ = outFile.Close()
		_ = rc.Close()
		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}

// ZipFiles compresses one or many files into a single zip archive file.
// Param 1: filename is the output zip file's name.
// Param 2: files is a list of files to add to the zip.
func zipFiles(filename string, files []string) error {
	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() { _ = newZipFile.Close() }()

	zipWriter := zip.NewWriter(newZipFile)
	defer func() { _ = zipWriter.Close() }()

	// Add files to zip
	for _, file := range files {
		if err = addFileToZip(zipWriter, file); err != nil {
			return err
		}
	}
	return nil
}

func addFileToZip(zipWriter *zip.Writer, filename string) error {
	fileToZip, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = fileToZip.Close() }()

	// Get the file information
	info, err := fileToZip.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	// Using FileInfoHeader() above only uses the basename of the file. If we want
	// to preserve the folder structure we can overwrite this with the full path.
	//header.Name = filename

	// Change to deflate to gain better compression
	// see http://golang.org/pkg/archive/zip/#pkg-constants
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, fileToZip)
	return err
}

func doIt(inputFilename string, outputDirectory string) {
	defer func() {
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *verbose {
				log.Println(err)
			}
			_, _ = os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(2)
		}
	}()
	if len(*executeModelMacro) > 0 {
		printLogo()
	} else {
		if *verbose {
			fmt.Println("Writing into output directory:", outputDirectory)
		}
	}

	model.Init()
	parseModel(inputFilename)
	introTextRAA := applyRAA()
	loadCustomRiskRules()
	applyRiskGeneration()
	applyWildcardRiskTrackingEvaluation()
	checkRiskTracking()

	if len(*executeModelMacro) > 0 {
		var macroDetails model.MacroDetails
		switch *executeModelMacro {
		case addbuildpipeline.GetMacroDetails().ID:
			macroDetails = addbuildpipeline.GetMacroDetails()
		case addvault.GetMacroDetails().ID:
			macroDetails = addvault.GetMacroDetails()
		case prettyprint.GetMacroDetails().ID:
			macroDetails = prettyprint.GetMacroDetails()
		case removeunusedtags.GetMacroDetails().ID:
			macroDetails = removeunusedtags.GetMacroDetails()
		case seedrisktracking.GetMacroDetails().ID:
			macroDetails = seedrisktracking.GetMacroDetails()
		case seedtags.GetMacroDetails().ID:
			macroDetails = seedtags.GetMacroDetails()
		default:
			log.Fatal("Unknown model macro: ", *executeModelMacro)
		}
		fmt.Println("Executing model macro:", macroDetails.ID)
		fmt.Println()
		fmt.Println()
		printBorder(len(macroDetails.Title), true)
		fmt.Println(macroDetails.Title)
		printBorder(len(macroDetails.Title), true)
		if len(macroDetails.Description) > 0 {
			fmt.Println(macroDetails.Description)
		}
		fmt.Println()
		reader := bufio.NewReader(os.Stdin)
		var err error
		var nextQuestion model.MacroQuestion
		for {
			switch macroDetails.ID {
			case addbuildpipeline.GetMacroDetails().ID:
				nextQuestion, err = addbuildpipeline.GetNextQuestion()
			case addvault.GetMacroDetails().ID:
				nextQuestion, err = addvault.GetNextQuestion()
			case prettyprint.GetMacroDetails().ID:
				nextQuestion, err = prettyprint.GetNextQuestion()
			case removeunusedtags.GetMacroDetails().ID:
				nextQuestion, err = removeunusedtags.GetNextQuestion()
			case seedrisktracking.GetMacroDetails().ID:
				nextQuestion, err = seedrisktracking.GetNextQuestion()
			case seedtags.GetMacroDetails().ID:
				nextQuestion, err = seedtags.GetNextQuestion()
			}
			checkErr(err)
			if nextQuestion.NoMoreQuestions() {
				break
			}
			fmt.Println()
			printBorder(len(nextQuestion.Title), false)
			fmt.Println(nextQuestion.Title)
			printBorder(len(nextQuestion.Title), false)
			if len(nextQuestion.Description) > 0 {
				fmt.Println(nextQuestion.Description)
			}
			resultingMultiValueSelection := make([]string, 0)
			if nextQuestion.IsValueConstrained() {
				if nextQuestion.MultiSelect {
					selectedValues := make(map[string]bool)
					for {
						fmt.Println("Please select (multiple executions possible) from the following values (use number to select/deselect):")
						fmt.Println("    0:", "SELECTION PROCESS FINISHED: CONTINUE TO NEXT QUESTION")
						for i, val := range nextQuestion.PossibleAnswers {
							number := i + 1
							padding, selected := "", " "
							if number < 10 {
								padding = " "
							}
							if val, exists := selectedValues[val]; exists && val {
								selected = "*"
							}
							fmt.Println(" "+selected+" "+padding+strconv.Itoa(number)+":", val)
						}
						fmt.Println()
						fmt.Print("Enter number to select/deselect (or 0 when finished): ")
						answer, err := reader.ReadString('\n')
						// convert CRLF to LF
						answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
						checkErr(err)
						if val, err := strconv.Atoi(answer); err == nil { // flip selection
							if val == 0 {
								for key, selected := range selectedValues {
									if selected {
										resultingMultiValueSelection = append(resultingMultiValueSelection, key)
									}
								}
								break
							} else if val > 0 && val <= len(nextQuestion.PossibleAnswers) {
								selectedValues[nextQuestion.PossibleAnswers[val-1]] = !selectedValues[nextQuestion.PossibleAnswers[val-1]]
							}
						}
					}
				} else {
					fmt.Println("Please choose from the following values (enter value directly or use number):")
					for i, val := range nextQuestion.PossibleAnswers {
						number := i + 1
						padding := ""
						if number < 10 {
							padding = " "
						}
						fmt.Println("   "+padding+strconv.Itoa(number)+":", val)
					}
				}
			}
			message := ""
			validResult := true
			if !nextQuestion.IsValueConstrained() || !nextQuestion.MultiSelect {
				fmt.Println()
				fmt.Println("Enter your answer (use 'BACK' to go one step back or 'QUIT' to quit without executing the model macro)")
				fmt.Print("Answer")
				if len(nextQuestion.DefaultAnswer) > 0 {
					fmt.Print(" (default '" + nextQuestion.DefaultAnswer + "')")
				}
				fmt.Print(": ")
				answer, err := reader.ReadString('\n')
				// convert CRLF to LF
				answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
				checkErr(err)
				if len(answer) == 0 && len(nextQuestion.DefaultAnswer) > 0 { // accepting the default
					answer = nextQuestion.DefaultAnswer
				} else if nextQuestion.IsValueConstrained() { // convert number to value
					if val, err := strconv.Atoi(answer); err == nil {
						if val > 0 && val <= len(nextQuestion.PossibleAnswers) {
							answer = nextQuestion.PossibleAnswers[val-1]
						}
					}
				}
				if strings.ToLower(answer) == "quit" {
					fmt.Println("Quitting without executing the model macro")
					return
				} else if strings.ToLower(answer) == "back" {
					switch macroDetails.ID {
					case addbuildpipeline.GetMacroDetails().ID:
						message, validResult, err = addbuildpipeline.GoBack()
					case addvault.GetMacroDetails().ID:
						message, validResult, err = addvault.GoBack()
					case prettyprint.GetMacroDetails().ID:
						message, validResult, err = prettyprint.GoBack()
					case removeunusedtags.GetMacroDetails().ID:
						message, validResult, err = removeunusedtags.GoBack()
					case seedrisktracking.GetMacroDetails().ID:
						message, validResult, err = seedrisktracking.GoBack()
					case seedtags.GetMacroDetails().ID:
						message, validResult, err = seedtags.GoBack()
					}
				} else if len(answer) > 0 { // individual answer
					if nextQuestion.IsValueConstrained() {
						if !nextQuestion.IsMatchingValueConstraint(answer) {
							fmt.Println()
							fmt.Println(">>> INVALID <<<")
							fmt.Println("Answer does not match any allowed value. Please try again:")
							continue
						}
					}
					switch macroDetails.ID {
					case addbuildpipeline.GetMacroDetails().ID:
						message, validResult, err = addbuildpipeline.ApplyAnswer(nextQuestion.ID, answer)
					case addvault.GetMacroDetails().ID:
						message, validResult, err = addvault.ApplyAnswer(nextQuestion.ID, answer)
					case prettyprint.GetMacroDetails().ID:
						message, validResult, err = prettyprint.ApplyAnswer(nextQuestion.ID, answer)
					case removeunusedtags.GetMacroDetails().ID:
						message, validResult, err = removeunusedtags.ApplyAnswer(nextQuestion.ID, answer)
					case seedrisktracking.GetMacroDetails().ID:
						message, validResult, err = seedrisktracking.ApplyAnswer(nextQuestion.ID, answer)
					case seedtags.GetMacroDetails().ID:
						message, validResult, err = seedtags.ApplyAnswer(nextQuestion.ID, answer)
					}
				}
			} else {
				switch macroDetails.ID {
				case addbuildpipeline.GetMacroDetails().ID:
					message, validResult, err = addbuildpipeline.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case addvault.GetMacroDetails().ID:
					message, validResult, err = addvault.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case prettyprint.GetMacroDetails().ID:
					message, validResult, err = prettyprint.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case removeunusedtags.GetMacroDetails().ID:
					message, validResult, err = removeunusedtags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case seedrisktracking.GetMacroDetails().ID:
					message, validResult, err = seedrisktracking.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case seedtags.GetMacroDetails().ID:
					message, validResult, err = seedtags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				}
			}
			checkErr(err)
			if !validResult {
				fmt.Println()
				fmt.Println(">>> INVALID <<<")
			}
			fmt.Println(message)
			fmt.Println()
		}
		for {
			fmt.Println()
			fmt.Println()
			fmt.Println("#################################################################")
			fmt.Println("Do you want to execute the model macro (updating the model file)?")
			fmt.Println("#################################################################")
			fmt.Println()
			fmt.Println("The following changes will be applied:")
			var changes []string
			message := ""
			validResult := true
			var err error
			switch macroDetails.ID {
			case addbuildpipeline.GetMacroDetails().ID:
				changes, message, validResult, err = addbuildpipeline.GetFinalChangeImpact(&modelInput)
			case addvault.GetMacroDetails().ID:
				changes, message, validResult, err = addvault.GetFinalChangeImpact(&modelInput)
			case prettyprint.GetMacroDetails().ID:
				changes, message, validResult, err = prettyprint.GetFinalChangeImpact(&modelInput)
			case removeunusedtags.GetMacroDetails().ID:
				changes, message, validResult, err = removeunusedtags.GetFinalChangeImpact(&modelInput)
			case seedrisktracking.GetMacroDetails().ID:
				changes, message, validResult, err = seedrisktracking.GetFinalChangeImpact(&modelInput)
			case seedtags.GetMacroDetails().ID:
				changes, message, validResult, err = seedtags.GetFinalChangeImpact(&modelInput)
			}
			checkErr(err)
			for _, change := range changes {
				fmt.Println(" -", change)
			}
			if !validResult {
				fmt.Println()
				fmt.Println(">>> INVALID <<<")
			}
			fmt.Println()
			fmt.Println(message)
			fmt.Println()
			fmt.Print("Apply these changes to the model file?\nType Yes or No: ")
			answer, err := reader.ReadString('\n')
			// convert CRLF to LF
			answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
			checkErr(err)
			answer = strings.ToLower(answer)
			fmt.Println()
			if answer == "yes" || answer == "y" {
				message := ""
				validResult := true
				var err error
				switch macroDetails.ID {
				case addbuildpipeline.GetMacroDetails().ID:
					message, validResult, err = addbuildpipeline.Execute(&modelInput)
				case addvault.GetMacroDetails().ID:
					message, validResult, err = addvault.Execute(&modelInput)
				case prettyprint.GetMacroDetails().ID:
					message, validResult, err = prettyprint.Execute(&modelInput)
				case removeunusedtags.GetMacroDetails().ID:
					message, validResult, err = removeunusedtags.Execute(&modelInput)
				case seedrisktracking.GetMacroDetails().ID:
					message, validResult, err = seedrisktracking.Execute(&modelInput)
				case seedtags.GetMacroDetails().ID:
					message, validResult, err = seedtags.Execute(&modelInput)
				}
				checkErr(err)
				if !validResult {
					fmt.Println()
					fmt.Println(">>> INVALID <<<")
				}
				fmt.Println(message)
				fmt.Println()
				backupFilename := inputFilename + ".backup"
				fmt.Println("Creating backup model file:", backupFilename) // TODO add random files in /dev/shm space?
				_, err = copyFile(inputFilename, backupFilename)
				checkErr(err)
				fmt.Println("Updating model")
				yamlBytes, err := yaml.Marshal(modelInput)
				checkErr(err)
				/*
					yamlBytes = model.ReformatYAML(yamlBytes)
				*/
				fmt.Println("Writing model file:", inputFilename)
				err = os.WriteFile(inputFilename, yamlBytes, 0400)
				checkErr(err)
				fmt.Println("Model file successfully updated")
				return
			} else if answer == "no" || answer == "n" {
				fmt.Println("Quitting without executing the model macro")
				return
			}
		}
		return
	}

	renderDataFlowDiagram, renderDataAssetDiagram, renderRisksJSON, renderTechnicalAssetsJSON, renderStatsJSON, renderRisksExcel, renderTagsExcel, renderPDF := *generateDataFlowDiagram, *generateDataAssetDiagram, *generateRisksJSON, *generateTechnicalAssetsJSON, *generateStatsJSON, *generateRisksExcel, *generateTagsExcel, *generateReportPDF
	if renderPDF { // as the PDF report includes both diagrams
		renderDataFlowDiagram, renderDataAssetDiagram = true, true
	}

	// Data-flow Diagram rendering
	if renderDataFlowDiagram {
		gvFile := outputDirectory + "/" + dataFlowDiagramFilenameDOT
		if !keepDiagramSourceFiles {
			tmpFileGV, err := os.CreateTemp(model.TempFolder, dataFlowDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFileGV.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := writeDataFlowDiagramGraphvizDOT(gvFile, *diagramDPI)
		renderDataFlowDiagramGraphvizImage(dotFile, outputDirectory)
	}
	// Data Asset Diagram rendering
	if renderDataAssetDiagram {
		gvFile := outputDirectory + "/" + dataAssetDiagramFilenameDOT
		if !keepDiagramSourceFiles {
			tmpFile, err := os.CreateTemp(model.TempFolder, dataAssetDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFile.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := writeDataAssetDiagramGraphvizDOT(gvFile, *diagramDPI)
		renderDataAssetDiagramGraphvizImage(dotFile, outputDirectory)
	}

	// risks as risks json
	if renderRisksJSON {
		if *verbose {
			fmt.Println("Writing risks json")
		}
		report.WriteRisksJSON(outputDirectory + "/" + jsonRisksFilename)
	}

	// technical assets json
	if renderTechnicalAssetsJSON {
		if *verbose {
			fmt.Println("Writing technical assets json")
		}
		report.WriteTechnicalAssetsJSON(outputDirectory + "/" + jsonTechnicalAssetsFilename)
	}

	// risks as risks json
	if renderStatsJSON {
		if *verbose {
			fmt.Println("Writing stats json")
		}
		report.WriteStatsJSON(outputDirectory + "/" + jsonStatsFilename)
	}

	// risks Excel
	if renderRisksExcel {
		if *verbose {
			fmt.Println("Writing risks excel")
		}
		report.WriteRisksExcelToFile(outputDirectory + "/" + excelRisksFilename)
	}

	// tags Excel
	if renderTagsExcel {
		if *verbose {
			fmt.Println("Writing tags excel")
		}
		report.WriteTagsExcelToFile(outputDirectory + "/" + excelTagsFilename)
	}

	if renderPDF {
		// hash the YAML input file
		f, err := os.Open(inputFilename)
		checkErr(err)
		defer func() { _ = f.Close() }()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			panic(err)
		}
		modelHash := hex.EncodeToString(hasher.Sum(nil))
		// report PDF
		if *verbose {
			fmt.Println("Writing report pdf")
		}
		report.WriteReportPDF(outputDirectory+"/"+reportFilename,
			*templateFilename,
			outputDirectory+"/"+dataFlowDiagramFilenamePNG,
			outputDirectory+"/"+dataAssetDiagramFilenamePNG,
			inputFilename,
			*skipRiskRules,
			buildTimestamp,
			modelHash,
			introTextRAA,
			customRiskRules)
	}
}

func printBorder(length int, bold bool) {
	char := "-"
	if bold {
		char = "="
	}
	for i := 1; i <= length; i++ {
		fmt.Print(char)
	}
	fmt.Println()
}

func applyRAA() string {
	if *verbose {
		fmt.Println("Applying RAA calculation:", *raaPlugin)
	}
	// determine plugin to load.
	// load plugin: open the ".so" file to load the symbols
	plug, err := plugin.Open(*raaPlugin)
	checkErr(err)
	// look up a symbol (an exported function or variable): in this case, function CalculateRAA
	symCalculateRAA, err := plug.Lookup("CalculateRAA")
	checkErr(err)
	// use the plugin
	raaCalcFunc, ok := symCalculateRAA.(func() string) // symCalculateRAA.(func(model.ParsedModel) string)
	if !ok {
		panic(errors.New("RAA plugin has no 'CalculateRAA() string' function"))
	}
	// call it
	return raaCalcFunc()
}

func loadCustomRiskRules() {
	customRiskRules = make(map[string]model.CustomRiskRule)
	if len(*riskRulesPlugins) > 0 {
		if *verbose {
			fmt.Println("Loading custom risk rules:", *riskRulesPlugins)
		}
		for _, pluginFile := range strings.Split(*riskRulesPlugins, ",") {
			if len(pluginFile) > 0 {
				// check that the plugin file to load exists
				_, err := os.Stat(pluginFile)
				if os.IsNotExist(err) {
					log.Fatal("Custom risk rule implementation file not found: ", pluginFile)
				}
				// load plugin: open the ".so" file to load the symbols
				plug, err := plugin.Open(pluginFile)
				checkErr(err)
				// look up a symbol (an exported function or variable): in this case variable CustomRiskRule
				symCustomRiskRule, err := plug.Lookup("CustomRiskRule")
				checkErr(err)
				// register the risk rule plugin for later use: in this case interface type model.CustomRiskRule (defined above)
				symCustomRiskRuleVar, ok := symCustomRiskRule.(model.CustomRiskRule)
				if !ok {
					panic(errors.New("custom risk rule plugin has no 'CustomRiskRule' variable"))
				}
				// simply add to a map (just convenience) where key is the category id and value the rule's execution function
				ruleID := symCustomRiskRuleVar.Category().Id
				customRiskRules[ruleID] = symCustomRiskRuleVar
				if *verbose {
					fmt.Println("Custom risk rule loaded:", ruleID)
				}
			}
		}
		if *verbose {
			fmt.Println("Loaded custom risk rules:", len(customRiskRules))
		}
	}
}

var validIdSyntax = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)

func checkIdSyntax(id string) {
	if !validIdSyntax.MatchString(id) {
		panic(errors.New("invalid id syntax used (only letters, numbers, and hyphen allowed): " + id))
	}
}

func analyze(context *gin.Context) {
	execute(context, false)
}
func check(context *gin.Context) {
	_, ok := execute(context, true)
	if ok {
		context.JSON(http.StatusOK, gin.H{
			"message": "model is ok",
		})
	}
}

func execute(context *gin.Context, dryRun bool) (yamlContent []byte, ok bool) {
	defer func() {
		var err error
		if r := recover(); r != nil {
			errorCount++
			err = r.(error)
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(context.DefaultQuery("dpi", strconv.Itoa(defaultGraphvizDPI)))
	checkErr(err)

	fileUploaded, header, err := context.Request.FormFile("file")
	checkErr(err)

	if header.Size > 50000000 {
		msg := "maximum model upload file size exceeded (denial-of-service protection)"
		log.Println(msg)
		context.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": msg,
		})
		return yamlContent, false
	}

	filenameUploaded := strings.TrimSpace(header.Filename)

	tmpInputDir, err := os.MkdirTemp(model.TempFolder, "threagile-input-")
	checkErr(err)
	defer func() { _ = os.RemoveAll(tmpInputDir) }()

	tmpModelFile, err := os.CreateTemp(tmpInputDir, "threagile-model-*")
	checkErr(err)
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	_, err = io.Copy(tmpModelFile, fileUploaded)
	checkErr(err)

	yamlFile := tmpModelFile.Name()

	if strings.ToLower(filepath.Ext(filenameUploaded)) == ".zip" {
		// unzip first (including the resources like images etc.)
		if *verbose {
			fmt.Println("Decompressing uploaded archive")
		}
		filenamesUnzipped, err := unzip(tmpModelFile.Name(), tmpInputDir)
		checkErr(err)
		found := false
		for _, name := range filenamesUnzipped {
			if strings.ToLower(filepath.Ext(name)) == ".yaml" {
				yamlFile = name
				found = true
				break
			}
		}
		if !found {
			panic(errors.New("no yaml file found in uploaded archive"))
		}
	}

	tmpOutputDir, err := os.MkdirTemp(model.TempFolder, "threagile-output-")
	checkErr(err)
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()

	tmpResultFile, err := os.CreateTemp(model.TempFolder, "threagile-result-*.zip")
	checkErr(err)
	defer func() { _ = os.Remove(tmpResultFile.Name()) }()

	if dryRun {
		doItViaRuntimeCall(yamlFile, tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, false, true, true, true, 40)
	} else {
		doItViaRuntimeCall(yamlFile, tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, true, true, true, true, true, true, true, true, dpi)
	}
	checkErr(err)

	yamlContent, err = os.ReadFile(yamlFile)
	checkErr(err)
	err = os.WriteFile(tmpOutputDir+"/threagile.yaml", yamlContent, 0400)
	checkErr(err)

	if !dryRun {
		files := []string{
			tmpOutputDir + "/threagile.yaml",
			tmpOutputDir + "/" + dataFlowDiagramFilenamePNG,
			tmpOutputDir + "/" + dataAssetDiagramFilenamePNG,
			tmpOutputDir + "/" + reportFilename,
			tmpOutputDir + "/" + excelRisksFilename,
			tmpOutputDir + "/" + excelTagsFilename,
			tmpOutputDir + "/" + jsonRisksFilename,
			tmpOutputDir + "/" + jsonTechnicalAssetsFilename,
			tmpOutputDir + "/" + jsonStatsFilename,
		}
		if keepDiagramSourceFiles {
			files = append(files, tmpOutputDir+"/"+dataFlowDiagramFilenameDOT)
			files = append(files, tmpOutputDir+"/"+dataAssetDiagramFilenameDOT)
		}
		err = zipFiles(tmpResultFile.Name(), files)
		checkErr(err)
		if *verbose {
			log.Println("Streaming back result file: " + tmpResultFile.Name())
		}
		context.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
	}
	successCount++
	return yamlContent, true
}

// ultimately to avoid any in-process memory and/or data leaks by the used third party libs like PDF generation: exec and quit
func doItViaRuntimeCall(modelFile string, outputDir string, executeModelMacro string, raaPlugin string, customRiskRulesPlugins string, skipRiskRules string, ignoreOrphanedRiskTracking bool,
	generateDataFlowDiagram, generateDataAssetDiagram, generateReportPdf, generateRisksExcel, generateTagsExcel, generateRisksJSON, generateTechnicalAssetsJSON, generateStatsJSON bool,
	dpi int) {
	// Remember to also add the same args to the exec based sub-process calls!
	var cmd *exec.Cmd
	args := []string{"-model", modelFile, "-output", outputDir, "-execute-model-macro", executeModelMacro, "-raa-plugin", raaPlugin, "-custom-risk-rules-plugins", customRiskRulesPlugins, "-skip-risk-rules", skipRiskRules, "-diagram-dpi", strconv.Itoa(dpi)}
	if *verbose {
		args = append(args, "-verbose")
	}
	if ignoreOrphanedRiskTracking { // TODO why add all them as arguments, when they are also variables on outer level?
		args = append(args, "-ignore-orphaned-risk-tracking")
	}
	if generateDataFlowDiagram {
		args = append(args, "-generate-data-flow-diagram")
	}
	if generateDataAssetDiagram {
		args = append(args, "-generate-data-asset-diagram")
	}
	if generateReportPdf {
		args = append(args, "-generate-report-pdf")
	}
	if generateRisksExcel {
		args = append(args, "-generate-risks-excel")
	}
	if generateTagsExcel {
		args = append(args, "-generate-tags-excel")
	}
	if generateRisksJSON {
		args = append(args, "-generate-risks-json")
	}
	if generateTechnicalAssetsJSON {
		args = append(args, "-generate-technical-assets-json")
	}
	if generateStatsJSON {
		args = append(args, "-generate-stats-json")
	}
	self := os.Args[0]
	cmd = exec.Command(self, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(errors.New(string(out)))
	} else {
		if *verbose && len(out) > 0 {
			fmt.Println("---")
			fmt.Print(string(out))
			fmt.Println("---")
		}
	}
}

func startServer() {
	router := gin.Default()
	router.LoadHTMLGlob("server/static/*.html")
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.HEAD("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.StaticFile("/threagile.png", "server/static/threagile.png")
	router.StaticFile("/site.webmanifest", "server/static/site.webmanifest")
	router.StaticFile("/favicon.ico", "server/static/favicon.ico")
	router.StaticFile("/favicon-32x32.png", "server/static/favicon-32x32.png")
	router.StaticFile("/favicon-16x16.png", "server/static/favicon-16x16.png")
	router.StaticFile("/apple-touch-icon.png", "server/static/apple-touch-icon.png")
	router.StaticFile("/android-chrome-512x512.png", "server/static/android-chrome-512x512.png")
	router.StaticFile("/android-chrome-192x192.png", "server/static/android-chrome-192x192.png")

	router.StaticFile("/schema.json", "schema.json")
	router.StaticFile("/live-templates.txt", "live-templates.txt")
	router.StaticFile("/openapi.yaml", "openapi.yaml")
	router.StaticFile("/swagger-ui/", "server/static/swagger-ui/index.html")
	router.StaticFile("/swagger-ui/index.html", "server/static/swagger-ui/index.html")
	router.StaticFile("/swagger-ui/oauth2-redirect.html", "server/static/swagger-ui/oauth2-redirect.html")
	router.StaticFile("/swagger-ui/swagger-ui.css", "server/static/swagger-ui/swagger-ui.css")
	router.StaticFile("/swagger-ui/swagger-ui.js", "server/static/swagger-ui/swagger-ui.js")
	router.StaticFile("/swagger-ui/swagger-ui-bundle.js", "server/static/swagger-ui/swagger-ui-bundle.js")
	router.StaticFile("/swagger-ui/swagger-ui-standalone-preset.js", "server/static/swagger-ui/swagger-ui-standalone-preset.js")

	router.GET("/threagile-example-model.yaml", exampleFile)
	router.GET("/threagile-stub-model.yaml", stubFile)

	router.GET("/meta/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	router.GET("/meta/version", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"version":         model.ThreagileVersion,
			"build_timestamp": buildTimestamp,
		})
	})
	router.GET("/meta/types", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"quantity":                     arrayOfStringValues(model.QuantityValues()),
			"confidentiality":              arrayOfStringValues(model.ConfidentialityValues()),
			"criticality":                  arrayOfStringValues(model.CriticalityValues()),
			"technical_asset_type":         arrayOfStringValues(model.TechnicalAssetTypeValues()),
			"technical_asset_size":         arrayOfStringValues(model.TechnicalAssetSizeValues()),
			"authorization":                arrayOfStringValues(model.AuthorizationValues()),
			"authentication":               arrayOfStringValues(model.AuthenticationValues()),
			"usage":                        arrayOfStringValues(model.UsageValues()),
			"encryption":                   arrayOfStringValues(model.EncryptionStyleValues()),
			"data_format":                  arrayOfStringValues(model.DataFormatValues()),
			"protocol":                     arrayOfStringValues(model.ProtocolValues()),
			"technical_asset_technology":   arrayOfStringValues(model.TechnicalAssetTechnologyValues()),
			"technical_asset_machine":      arrayOfStringValues(model.TechnicalAssetMachineValues()),
			"trust_boundary_type":          arrayOfStringValues(model.TrustBoundaryTypeValues()),
			"data_breach_probability":      arrayOfStringValues(model.DataBreachProbabilityValues()),
			"risk_severity":                arrayOfStringValues(model.RiskSeverityValues()),
			"risk_exploitation_likelihood": arrayOfStringValues(model.RiskExploitationLikelihoodValues()),
			"risk_exploitation_impact":     arrayOfStringValues(model.RiskExploitationImpactValues()),
			"risk_function":                arrayOfStringValues(model.RiskFunctionValues()),
			"risk_status":                  arrayOfStringValues(model.RiskStatusValues()),
			"stride":                       arrayOfStringValues(model.STRIDEValues()),
		})
	})

	// TODO router.GET("/meta/risk-rules", listRiskRules)
	// TODO router.GET("/meta/model-macros", listModelMacros)

	router.GET("/meta/stats", stats)

	router.POST("/direct/analyze", analyze)
	router.POST("/direct/check", check)
	router.GET("/direct/stub", stubFile)

	router.POST("/auth/keys", createKey)
	router.DELETE("/auth/keys", deleteKey)
	router.POST("/auth/tokens", createToken)
	router.DELETE("/auth/tokens", deleteToken)

	router.POST("/models", createNewModel)
	router.GET("/models", listModels)
	router.DELETE("/models/:model-id", deleteModel)
	router.GET("/models/:model-id", getModel)
	router.PUT("/models/:model-id", importModel)
	router.GET("/models/:model-id/data-flow-diagram", streamDataFlowDiagram)
	router.GET("/models/:model-id/data-asset-diagram", streamDataAssetDiagram)
	router.GET("/models/:model-id/report-pdf", streamReportPDF)
	router.GET("/models/:model-id/risks-excel", streamRisksExcel)
	router.GET("/models/:model-id/tags-excel", streamTagsExcel)
	router.GET("/models/:model-id/risks", streamRisksJSON)
	router.GET("/models/:model-id/technical-assets", streamTechnicalAssetsJSON)
	router.GET("/models/:model-id/stats", streamStatsJSON)
	router.GET("/models/:model-id/analysis", analyzeModelOnServerDirectly)

	router.GET("/models/:model-id/cover", getCover)
	router.PUT("/models/:model-id/cover", setCover)
	router.GET("/models/:model-id/overview", getOverview)
	router.PUT("/models/:model-id/overview", setOverview)
	//router.GET("/models/:model-id/questions", getQuestions)
	//router.PUT("/models/:model-id/questions", setQuestions)
	router.GET("/models/:model-id/abuse-cases", getAbuseCases)
	router.PUT("/models/:model-id/abuse-cases", setAbuseCases)
	router.GET("/models/:model-id/security-requirements", getSecurityRequirements)
	router.PUT("/models/:model-id/security-requirements", setSecurityRequirements)
	//router.GET("/models/:model-id/tags", getTags)
	//router.PUT("/models/:model-id/tags", setTags)

	router.GET("/models/:model-id/data-assets", getDataAssets)
	router.POST("/models/:model-id/data-assets", createNewDataAsset)
	router.GET("/models/:model-id/data-assets/:data-asset-id", getDataAsset)
	router.PUT("/models/:model-id/data-assets/:data-asset-id", setDataAsset)
	router.DELETE("/models/:model-id/data-assets/:data-asset-id", deleteDataAsset)

	router.GET("/models/:model-id/trust-boundaries", getTrustBoundaries)
	//	router.POST("/models/:model-id/trust-boundaries", createNewTrustBoundary)
	//	router.GET("/models/:model-id/trust-boundaries/:trust-boundary-id", getTrustBoundary)
	//	router.PUT("/models/:model-id/trust-boundaries/:trust-boundary-id", setTrustBoundary)
	//	router.DELETE("/models/:model-id/trust-boundaries/:trust-boundary-id", deleteTrustBoundary)

	router.GET("/models/:model-id/shared-runtimes", getSharedRuntimes)
	router.POST("/models/:model-id/shared-runtimes", createNewSharedRuntime)
	router.GET("/models/:model-id/shared-runtimes/:shared-runtime-id", getSharedRuntime)
	router.PUT("/models/:model-id/shared-runtimes/:shared-runtime-id", setSharedRuntime)
	router.DELETE("/models/:model-id/shared-runtimes/:shared-runtime-id", deleteSharedRuntime)

	fmt.Println("Threagile server running...")
	_ = router.Run(":" + strconv.Itoa(*serverPort)) // listen and serve on 0.0.0.0:8080 or whatever port was specified
}

func exampleFile(context *gin.Context) {
	example, err := os.ReadFile("/app/threagile-example-model.yaml")
	checkErr(err)
	context.Data(http.StatusOK, gin.MIMEYAML, example)
}

func stubFile(context *gin.Context) {
	stub, err := os.ReadFile("/app/threagile-stub-model.yaml")
	checkErr(err)
	context.Data(http.StatusOK, gin.MIMEYAML, addSupportedTags(stub)) // TODO use also the MIMEYAML way of serving YAML in model export?
}

func addSupportedTags(input []byte) []byte {
	// add distinct tags as "tags_available"
	supportedTags := make(map[string]bool)
	for _, customRule := range customRiskRules {
		for _, tag := range customRule.SupportedTags() {
			supportedTags[strings.ToLower(tag)] = true
		}
	}
	for _, tag := range accidentalsecretleak.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range codebackdooring.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range containerbaseimagebackdooring.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range containerplatformescape.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range crosssiterequestforgery.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range crosssitescripting.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range dosriskyaccessacrosstrustboundary.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range incompletemodel.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range ldapinjection.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingauthentication.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingauthenticationsecondfactor.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingbuildinfrastructure.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingcloudhardening.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingfilevalidation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missinghardening.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingidentitypropagation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingidentityproviderisolation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingidentitystore.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingnetworksegmentation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingvault.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingvaultisolation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingwaf.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range mixedtargetsonsharedruntime.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range pathtraversal.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range pushinsteadofpulldeployment.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range searchqueryinjection.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range serversiderequestforgery.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range serviceregistrypoisoning.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range sqlnosqlinjection.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range uncheckeddeployment.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unencryptedasset.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unencryptedcommunication.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unguardedaccessfrominternet.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unguardeddirectdatastoreaccess.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessarycommunicationlink.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessarydataasset.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessarydatatransfer.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessarytechnicalasset.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range untrusteddeserialization.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range wrongcommunicationlinkcontent.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range wrongtrustboundarycontent.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range xmlexternalentity.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	tags := make([]string, 0, len(supportedTags))
	for t := range supportedTags {
		tags = append(tags, t)
	}
	if len(tags) == 0 {
		return input
	}
	sort.Strings(tags)
	if *verbose {
		fmt.Print("Supported tags of all risk rules: ")
		for i, tag := range tags {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(tag)
		}
		fmt.Println()
	}
	replacement := "tags_available:"
	for _, tag := range tags {
		replacement += "\n  - " + tag
	}
	return []byte(strings.Replace(string(input), "tags_available:", replacement, 1))
}

const keySize = 32

type timeoutStruct struct {
	xorRand                               []byte
	createdNanoTime, lastAccessedNanoTime int64
}

var mapTokenHashToTimeoutStruct = make(map[string]timeoutStruct)
var mapFolderNameToTokenHash = make(map[string]string)

func createToken(context *gin.Context) {
	folderName, key, ok := checkKeyToFolderName(context)
	if !ok {
		return
	}
	globalLock.Lock()
	defer globalLock.Unlock()
	if tokenHash, exists := mapFolderNameToTokenHash[folderName]; exists {
		// invalidate previous token
		delete(mapTokenHashToTimeoutStruct, tokenHash)
	}
	// create a strong random 256 bit value (used to xor)
	xorBytesArr := make([]byte, keySize)
	n, err := rand.Read(xorBytesArr[:])
	if n != keySize || err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create token",
		})
		return
	}
	now := time.Now().UnixNano()
	token := xor(key, xorBytesArr)
	tokenHash := hashSHA256(token)
	housekeepingTokenMaps()
	mapTokenHashToTimeoutStruct[tokenHash] = timeoutStruct{
		xorRand:              xorBytesArr,
		createdNanoTime:      now,
		lastAccessedNanoTime: now,
	}
	mapFolderNameToTokenHash[folderName] = tokenHash
	context.JSON(http.StatusCreated, gin.H{
		"token": base64.RawURLEncoding.EncodeToString(token[:]),
	})
}

func deleteToken(context *gin.Context) {
	header := tokenHeader{}
	if err := context.ShouldBindHeader(&header); err != nil {
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Token))
	if len(token) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	globalLock.Lock()
	defer globalLock.Unlock()
	deleteTokenHashFromMaps(hashSHA256(token))
	context.JSON(http.StatusOK, gin.H{
		"message": "token deleted",
	})
}

const extremeShortTimeoutsForTesting = false

func housekeepingTokenMaps() {
	now := time.Now().UnixNano()
	for tokenHash, val := range mapTokenHashToTimeoutStruct {
		if extremeShortTimeoutsForTesting {
			// remove all elements older than 1 minute (= 60000000000 ns) soft
			// and all elements older than 3 minutes (= 180000000000 ns) hard
			if now-val.lastAccessedNanoTime > 60000000000 || now-val.createdNanoTime > 180000000000 {
				fmt.Println("About to remove a token hash from maps")
				deleteTokenHashFromMaps(tokenHash)
			}
		} else {
			// remove all elements older than 30 minutes (= 1800000000000 ns) soft
			// and all elements older than 10 hours (= 36000000000000 ns) hard
			if now-val.lastAccessedNanoTime > 1800000000000 || now-val.createdNanoTime > 36000000000000 {
				deleteTokenHashFromMaps(tokenHash)
			}
		}
	}
}

func deleteTokenHashFromMaps(tokenHash string) {
	delete(mapTokenHashToTimeoutStruct, tokenHash)
	for folderName, check := range mapFolderNameToTokenHash {
		if check == tokenHash {
			delete(mapFolderNameToTokenHash, folderName)
			break
		}
	}
}

func xor(key []byte, xor []byte) []byte {
	if len(key) != len(xor) {
		panic(errors.New("key length not matching XOR length"))
	}
	result := make([]byte, len(xor))
	for i, b := range key {
		result[i] = b ^ xor[i]
	}
	return result
}

func analyzeModelOnServerDirectly(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer func() {
		unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *verbose {
				log.Println(err)
			}
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(context.DefaultQuery("dpi", strconv.Itoa(defaultGraphvizDPI)))
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}

	_, yamlText, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := os.CreateTemp(model.TempFolder, "threagile-direct-analyze-*")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	tmpOutputDir, err := os.MkdirTemp(model.TempFolder, "threagile-direct-analyze-")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	tmpResultFile, err := os.CreateTemp(model.TempFolder, "threagile-result-*.zip")
	checkErr(err)
	defer func() { _ = os.Remove(tmpResultFile.Name()) }()

	err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)

	doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, true, true, true, true, true, true, true, true, dpi)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	err = os.WriteFile(tmpOutputDir+"/threagile.yaml", []byte(yamlText), 0400)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}

	files := []string{
		tmpOutputDir + "/threagile.yaml",
		tmpOutputDir + "/" + dataFlowDiagramFilenamePNG,
		tmpOutputDir + "/" + dataAssetDiagramFilenamePNG,
		tmpOutputDir + "/" + reportFilename,
		tmpOutputDir + "/" + excelRisksFilename,
		tmpOutputDir + "/" + excelTagsFilename,
		tmpOutputDir + "/" + jsonRisksFilename,
		tmpOutputDir + "/" + jsonTechnicalAssetsFilename,
		tmpOutputDir + "/" + jsonStatsFilename,
	}
	if keepDiagramSourceFiles {
		files = append(files, tmpOutputDir+"/"+dataFlowDiagramFilenameDOT)
		files = append(files, tmpOutputDir+"/"+dataAssetDiagramFilenameDOT)
	}
	err = zipFiles(tmpResultFile.Name(), files)
	checkErr(err)
	if *verbose {
		fmt.Println("Streaming back result file: " + tmpResultFile.Name())
	}
	context.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
}

type responseType int

const (
	dataFlowDiagram responseType = iota
	dataAssetDiagram
	reportPDF
	risksExcel
	tagsExcel
	risksJSON
	technicalAssetsJSON
	statsJSON
)

func streamDataFlowDiagram(context *gin.Context) {
	streamResponse(context, dataFlowDiagram)
}
func streamDataAssetDiagram(context *gin.Context) {
	streamResponse(context, dataAssetDiagram)
}
func streamReportPDF(context *gin.Context) {
	streamResponse(context, reportPDF)
}
func streamRisksExcel(context *gin.Context) {
	streamResponse(context, risksExcel)
}
func streamTagsExcel(context *gin.Context) {
	streamResponse(context, tagsExcel)
}
func streamRisksJSON(context *gin.Context) {
	streamResponse(context, risksJSON)
}
func streamTechnicalAssetsJSON(context *gin.Context) {
	streamResponse(context, technicalAssetsJSON)
}
func streamStatsJSON(context *gin.Context) {
	streamResponse(context, statsJSON)
}
func streamResponse(context *gin.Context, responseType responseType) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer func() {
		unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *verbose {
				log.Println(err)
			}
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()
	dpi, err := strconv.Atoi(context.DefaultQuery("dpi", strconv.Itoa(defaultGraphvizDPI)))
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	_, yamlText, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := os.CreateTemp(model.TempFolder, "threagile-render-*")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	tmpOutputDir, err := os.MkdirTemp(model.TempFolder, "threagile-render-")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)
	if responseType == dataFlowDiagram {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, true, false, false, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.File(tmpOutputDir + "/" + dataFlowDiagramFilenamePNG)
	} else if responseType == dataAssetDiagram {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, false, true, false, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.File(tmpOutputDir + "/" + dataAssetDiagramFilenamePNG)
	} else if responseType == reportPDF {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, true, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.FileAttachment(tmpOutputDir+"/"+reportFilename, reportFilename)
	} else if responseType == risksExcel {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, true, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.FileAttachment(tmpOutputDir+"/"+excelRisksFilename, excelRisksFilename)
	} else if responseType == tagsExcel {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, true, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.FileAttachment(tmpOutputDir+"/"+excelTagsFilename, excelTagsFilename)
	} else if responseType == risksJSON {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, false, true, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		json, err := os.ReadFile(tmpOutputDir + "/" + jsonRisksFilename)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.Data(http.StatusOK, "application/json", json) // stream directly with JSON content-type in response instead of file download
	} else if responseType == technicalAssetsJSON {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, false, true, true, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		json, err := os.ReadFile(tmpOutputDir + "/" + jsonTechnicalAssetsFilename)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.Data(http.StatusOK, "application/json", json) // stream directly with JSON content-type in response instead of file download
	} else if responseType == statsJSON {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, false, false, false, true, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		json, err := os.ReadFile(tmpOutputDir + "/" + jsonStatsFilename)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.Data(http.StatusOK, "application/json", json) // stream directly with JSON content-type in response instead of file download
	}
}

// fully replaces threagile.yaml in sub-folder given by UUID
func importModel(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)

	aUuid := context.Param("model-id") // UUID is syntactically validated in readModel+checkModelFolder (next line) via uuid.Parse(modelUUID)
	_, _, ok = readModel(context, aUuid, key, folderNameOfKey)
	if ok {
		// first analyze it simply by executing the full risk process (just discard the result) to ensure that everything would work
		yamlContent, ok := execute(context, true)
		if ok {
			// if we're here, then no problem was raised, so ok to proceed
			ok = writeModelYAML(context, string(yamlContent), key, folderNameForModel(folderNameOfKey, aUuid), "Model Import", false)
			if ok {
				context.JSON(http.StatusCreated, gin.H{
					"message": "model imported",
				})
			}
		}
	}
}

func stats(context *gin.Context) {
	keyCount, modelCount := 0, 0
	keyFolders, err := os.ReadDir(baseFolder)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to collect stats",
		})
		return
	}
	for _, keyFolder := range keyFolders {
		if len(keyFolder.Name()) == 128 { // it's a sha512 token hash probably, so count it as token folder for the stats
			keyCount++
			modelFolders, err := os.ReadDir(baseFolder + "/" + keyFolder.Name())
			if err != nil {
				log.Println(err)
				context.JSON(http.StatusInternalServerError, gin.H{
					"error": "unable to collect stats",
				})
				return
			}
			for _, modelFolder := range modelFolders {
				if len(modelFolder.Name()) == 36 { // it's a uuid model folder probably, so count it as model folder for the stats
					modelCount++
				}
			}
		}
	}
	// TODO collect and deliver more stats (old model count?) and health info
	context.JSON(http.StatusOK, gin.H{
		"key_count":     keyCount,
		"model_count":   modelCount,
		"success_count": successCount,
		"error_count":   errorCount,
	})
}

func getDataAsset(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == context.Param("data-asset-id") {
				context.JSON(http.StatusOK, gin.H{
					title: dataAsset,
				})
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func deleteDataAsset(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == context.Param("data-asset-id") {
				// also remove all usages of this data asset !!
				for _, techAsset := range modelInput.TechnicalAssets {
					if techAsset.DataAssetsProcessed != nil {
						for i, parsedChangeCandidateAsset := range techAsset.DataAssetsProcessed {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.DataAssetsProcessed[i:], techAsset.DataAssetsProcessed[i+1:])                         // Shift a[i+1:] left one index.
								techAsset.DataAssetsProcessed[len(techAsset.DataAssetsProcessed)-1] = ""                             // Erase last element (write zero value).
								techAsset.DataAssetsProcessed = techAsset.DataAssetsProcessed[:len(techAsset.DataAssetsProcessed)-1] // Truncate slice.
							}
						}
					}
					if techAsset.DataAssetsStored != nil {
						for i, parsedChangeCandidateAsset := range techAsset.DataAssetsStored {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.DataAssetsStored[i:], techAsset.DataAssetsStored[i+1:])                      // Shift a[i+1:] left one index.
								techAsset.DataAssetsStored[len(techAsset.DataAssetsStored)-1] = ""                          // Erase last element (write zero value).
								techAsset.DataAssetsStored = techAsset.DataAssetsStored[:len(techAsset.DataAssetsStored)-1] // Truncate slice.
							}
						}
					}
					if techAsset.CommunicationLinks != nil {
						for title, commLink := range techAsset.CommunicationLinks {
							for i, dataAssetSent := range commLink.DataAssetsSent {
								referencedAsset := fmt.Sprintf("%v", dataAssetSent)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.CommunicationLinks[title].DataAssetsSent[i:], techAsset.CommunicationLinks[title].DataAssetsSent[i+1:]) // Shift a[i+1:] left one index.
									techAsset.CommunicationLinks[title].DataAssetsSent[len(techAsset.CommunicationLinks[title].DataAssetsSent)-1] = ""     // Erase last element (write zero value).
									x := techAsset.CommunicationLinks[title]
									x.DataAssetsSent = techAsset.CommunicationLinks[title].DataAssetsSent[:len(techAsset.CommunicationLinks[title].DataAssetsSent)-1] // Truncate slice.
									techAsset.CommunicationLinks[title] = x
								}
							}
							for i, dataAssetReceived := range commLink.DataAssetsReceived {
								referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.CommunicationLinks[title].DataAssetsReceived[i:], techAsset.CommunicationLinks[title].DataAssetsReceived[i+1:]) // Shift a[i+1:] left one index.
									techAsset.CommunicationLinks[title].DataAssetsReceived[len(techAsset.CommunicationLinks[title].DataAssetsReceived)-1] = ""     // Erase last element (write zero value).
									x := techAsset.CommunicationLinks[title]
									x.DataAssetsReceived = techAsset.CommunicationLinks[title].DataAssetsReceived[:len(techAsset.CommunicationLinks[title].DataAssetsReceived)-1] // Truncate slice.
									techAsset.CommunicationLinks[title] = x
								}
							}
						}
					}
				}
				for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
					if individualRiskCat.RisksIdentified != nil {
						for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
							if individualRiskInstance.MostRelevantDataAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
								x.MostRelevantDataAsset = "" // TODO needs more testing
								modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.DataAssets, title)
				ok = writeModel(context, key, folderNameOfKey, &modelInput, "Data Asset Deletion")
				if ok {
					context.JSON(http.StatusOK, gin.H{
						"message":            "data asset deleted",
						"id":                 dataAsset.ID,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func setSharedRuntime(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == context.Param("shared-runtime-id") {
				payload := payloadSharedRuntime{}
				err := context.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					context.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
					return
				}
				sharedRuntimeInput, ok := populateSharedRuntime(context, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the shared runtime from the map and re-insert it (with new key)
				delete(modelInput.SharedRuntimes, title)
				modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
				idChanged := sharedRuntimeInput.ID != sharedRuntime.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
						if individualRiskCat.RisksIdentified != nil {
							for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
								if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the ID change
									x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
									x.MostRelevantSharedRuntime = sharedRuntimeInput.ID // TODO needs more testing
									modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				ok = writeModel(context, key, folderNameOfKey, &modelInput, "Shared Runtime Update")
				if ok {
					context.JSON(http.StatusOK, gin.H{
						"message":    "shared runtime updated",
						"id":         sharedRuntimeInput.ID,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func setDataAsset(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == context.Param("data-asset-id") {
				payload := payloadDataAsset{}
				err := context.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					context.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
					return
				}
				dataAssetInput, ok := populateDataAsset(context, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the asset from the map and re-insert it (with new key)
				delete(modelInput.DataAssets, title)
				modelInput.DataAssets[payload.Title] = dataAssetInput
				idChanged := dataAssetInput.ID != dataAsset.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					// also update all usages to point to the new (changed) ID !!
					for techAssetTitle, techAsset := range modelInput.TechnicalAssets {
						if techAsset.DataAssetsProcessed != nil {
							for i, parsedChangeCandidateAsset := range techAsset.DataAssetsProcessed {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.TechnicalAssets[techAssetTitle].DataAssetsProcessed[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.DataAssetsStored != nil {
							for i, parsedChangeCandidateAsset := range techAsset.DataAssetsStored {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.TechnicalAssets[techAssetTitle].DataAssetsStored[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.CommunicationLinks != nil {
							for title, commLink := range techAsset.CommunicationLinks {
								for i, dataAssetSent := range commLink.DataAssetsSent {
									referencedAsset := fmt.Sprintf("%v", dataAssetSent)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsSent[i] = dataAssetInput.ID
									}
								}
								for i, dataAssetReceived := range commLink.DataAssetsReceived {
									referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsReceived[i] = dataAssetInput.ID
									}
								}
							}
						}
					}
					for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
						if individualRiskCat.RisksIdentified != nil {
							for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
								if individualRiskInstance.MostRelevantDataAsset == dataAsset.ID { // apply the ID change
									x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
									x.MostRelevantDataAsset = dataAssetInput.ID // TODO needs more testing
									modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				ok = writeModel(context, key, folderNameOfKey, &modelInput, "Data Asset Update")
				if ok {
					context.JSON(http.StatusOK, gin.H{
						"message":    "data asset updated",
						"id":         dataAssetInput.ID,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func getSharedRuntime(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == context.Param("shared-runtime-id") {
				context.JSON(http.StatusOK, gin.H{
					title: sharedRuntime,
				})
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func createNewSharedRuntime(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSharedRuntime{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.SharedRuntimes[payload.Title]; exists {
			context.JSON(http.StatusConflict, gin.H{
				"error": "shared runtime with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, runtime := range modelInput.SharedRuntimes {
			if runtime.ID == payload.Id {
				context.JSON(http.StatusConflict, gin.H{
					"error": "shared runtime with this id already exists",
				})
				return
			}
		}
		if !checkTechnicalAssetsExisting(modelInput, payload.TechnicalAssetsRunning) {
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "referenced technical asset does not exist",
			})
			return
		}
		sharedRuntimeInput, ok := populateSharedRuntime(context, payload)
		if !ok {
			return
		}
		if modelInput.SharedRuntimes == nil {
			modelInput.SharedRuntimes = make(map[string]model.InputSharedRuntime)
		}
		modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Shared Runtime Creation")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "shared runtime created",
				"id":      sharedRuntimeInput.ID,
			})
		}
	}
}

func checkTechnicalAssetsExisting(modelInput model.ModelInput, techAssetIDs []string) (ok bool) {
	for _, techAssetID := range techAssetIDs {
		exists := false
		for _, val := range modelInput.TechnicalAssets {
			if val.ID == techAssetID {
				exists = true
				break
			}
		}
		if !exists {
			return false
		}
	}
	return true
}

func populateSharedRuntime(_ *gin.Context, payload payloadSharedRuntime) (sharedRuntimeInput model.InputSharedRuntime, ok bool) {
	sharedRuntimeInput = model.InputSharedRuntime{
		ID:                     payload.Id,
		Description:            payload.Description,
		Tags:                   lowerCaseAndTrim(payload.Tags),
		TechnicalAssetsRunning: payload.TechnicalAssetsRunning,
	}
	return sharedRuntimeInput, true
}

func deleteSharedRuntime(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == context.Param("shared-runtime-id") {
				// also remove all usages of this shared runtime !!
				for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
					if individualRiskCat.RisksIdentified != nil {
						for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
							if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
								x.MostRelevantSharedRuntime = "" // TODO needs more testing
								modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.SharedRuntimes, title)
				ok = writeModel(context, key, folderNameOfKey, &modelInput, "Shared Runtime Deletion")
				if ok {
					context.JSON(http.StatusOK, gin.H{
						"message":            "shared runtime deleted",
						"id":                 sharedRuntime.ID,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func createNewDataAsset(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadDataAsset{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.DataAssets[payload.Title]; exists {
			context.JSON(http.StatusConflict, gin.H{
				"error": "data asset with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, asset := range modelInput.DataAssets {
			if asset.ID == payload.Id {
				context.JSON(http.StatusConflict, gin.H{
					"error": "data asset with this id already exists",
				})
				return
			}
		}
		dataAssetInput, ok := populateDataAsset(context, payload)
		if !ok {
			return
		}
		if modelInput.DataAssets == nil {
			modelInput.DataAssets = make(map[string]model.InputDataAsset)
		}
		modelInput.DataAssets[payload.Title] = dataAssetInput
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Data Asset Creation")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "data asset created",
				"id":      dataAssetInput.ID,
			})
		}
	}
}

func populateDataAsset(context *gin.Context, payload payloadDataAsset) (dataAssetInput model.InputDataAsset, ok bool) {
	usage, err := model.ParseUsage(payload.Usage)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	quantity, err := model.ParseQuantity(payload.Quantity)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	confidentiality, err := model.ParseConfidentiality(payload.Confidentiality)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	integrity, err := model.ParseCriticality(payload.Integrity)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	availability, err := model.ParseCriticality(payload.Availability)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	dataAssetInput = model.InputDataAsset{
		ID:                     payload.Id,
		Description:            payload.Description,
		Usage:                  usage.String(),
		Tags:                   lowerCaseAndTrim(payload.Tags),
		Origin:                 payload.Origin,
		Owner:                  payload.Owner,
		Quantity:               quantity.String(),
		Confidentiality:        confidentiality.String(),
		Integrity:              integrity.String(),
		Availability:           availability.String(),
		JustificationCiaRating: payload.JustificationCiaRating,
	}
	return dataAssetInput, true
}

func getDataAssets(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	aModel, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, aModel.DataAssets)
	}
}

func getTrustBoundaries(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	aModel, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, aModel.TrustBoundaries)
	}
}

func getSharedRuntimes(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	aModel, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, aModel.SharedRuntimes)
	}
}

func arrayOfStringValues(values []model.TypeEnum) []string {
	result := make([]string, 0)
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}

func getModel(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	_, yamlText, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		tmpResultFile, err := os.CreateTemp(model.TempFolder, "threagile-*.yaml")
		checkErr(err)
		err = os.WriteFile(tmpResultFile.Name(), []byte(yamlText), 0400)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to stream model file",
			})
			return
		}
		defer func() { _ = os.Remove(tmpResultFile.Name()) }()
		context.FileAttachment(tmpResultFile.Name(), "threagile.yaml")
	}
}

type payloadModels struct {
	ID                string    `json:"id"`
	Title             string    `json:"title"`
	TimestampCreated  time.Time `json:"timestamp_created"`
	TimestampModified time.Time `json:"timestamp_modified"`
}

type payloadCover struct {
	Title  string       `json:"title"`
	Date   time.Time    `json:"date"`
	Author model.Author `json:"author"`
}

type payloadOverview struct {
	ManagementSummaryComment string         `json:"management_summary_comment"`
	BusinessCriticality      string         `json:"business_criticality"`
	BusinessOverview         model.Overview `json:"business_overview"`
	TechnicalOverview        model.Overview `json:"technical_overview"`
}

type payloadAbuseCases map[string]string

type payloadSecurityRequirements map[string]string

type payloadDataAsset struct {
	Title                  string   `json:"title"`
	Id                     string   `json:"id"`
	Description            string   `json:"description"`
	Usage                  string   `json:"usage"`
	Tags                   []string `json:"tags"`
	Origin                 string   `json:"origin"`
	Owner                  string   `json:"owner"`
	Quantity               string   `json:"quantity"`
	Confidentiality        string   `json:"confidentiality"`
	Integrity              string   `json:"integrity"`
	Availability           string   `json:"availability"`
	JustificationCiaRating string   `json:"justification_cia_rating"`
}

type payloadSharedRuntime struct {
	Title                  string   `json:"title"`
	Id                     string   `json:"id"`
	Description            string   `json:"description"`
	Tags                   []string `json:"tags"`
	TechnicalAssetsRunning []string `json:"technical_assets_running"`
}

func setSecurityRequirements(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSecurityRequirements{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.SecurityRequirements = payload
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Security Requirements Update")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func getSecurityRequirements(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	aModel, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, aModel.SecurityRequirements)
	}
}

func setAbuseCases(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadAbuseCases{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.AbuseCases = payload
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Abuse Cases Update")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func getAbuseCases(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	aModel, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, aModel.AbuseCases)
	}
}

func setOverview(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadOverview{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		criticality, err := model.ParseCriticality(payload.BusinessCriticality)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		modelInput.ManagementSummaryComment = payload.ManagementSummaryComment
		modelInput.BusinessCriticality = criticality.String()
		modelInput.BusinessOverview.Description = payload.BusinessOverview.Description
		modelInput.BusinessOverview.Images = payload.BusinessOverview.Images
		modelInput.TechnicalOverview.Description = payload.TechnicalOverview.Description
		modelInput.TechnicalOverview.Images = payload.TechnicalOverview.Images
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Overview Update")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func handleErrorInServiceCall(err error, context *gin.Context) {
	log.Println(err)
	context.JSON(http.StatusBadRequest, gin.H{
		"error": strings.TrimSpace(err.Error()),
	})
}

func getOverview(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	aModel, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, gin.H{
			"management_summary_comment": aModel.ManagementSummaryComment,
			"business_criticality":       aModel.BusinessCriticality,
			"business_overview":          aModel.BusinessOverview,
			"technical_overview":         aModel.TechnicalOverview,
		})
	}
}

func setCover(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadCover{}
		err := context.BindJSON(&payload)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.Title = payload.Title
		if !payload.Date.IsZero() {
			modelInput.Date = payload.Date.Format("2006-01-02")
		}
		modelInput.Author.Name = payload.Author.Name
		modelInput.Author.Homepage = payload.Author.Homepage
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Cover Update")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func getCover(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	aModel, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, gin.H{
			"title":  aModel.Title,
			"date":   aModel.Date,
			"author": aModel.Author,
		})
	}
}

// creates a sub-folder (named by a new UUID) inside the token folder
func createNewModel(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	ok = checkObjectCreationThrottler(context, "MODEL")
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)

	aUuid := uuid.New().String()
	err := os.Mkdir(folderNameForModel(folderNameOfKey, aUuid), 0700)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create model",
		})
		return
	}

	aYaml := `title: New Threat Model
threagile_version: ` + model.ThreagileVersion + `
author:
  name: ""
  homepage: ""
date:
business_overview:
  description: ""
  images: []
technical_overview:
  description: ""
  images: []
business_criticality: ""
management_summary_comment: ""
questions: {}
abuse_cases: {}
security_requirements: {}
tags_available: []
data_assets: {}
technical_assets: {}
trust_boundaries: {}
shared_runtimes: {}
individual_risk_categories: {}
risk_tracking: {}
diagram_tweak_nodesep: ""
diagram_tweak_ranksep: ""
diagram_tweak_edge_layout: ""
diagram_tweak_suppress_edge_labels: false
diagram_tweak_invisible_connections_between_assets: []
diagram_tweak_same_rank_assets: []`

	ok = writeModelYAML(context, aYaml, key, folderNameForModel(folderNameOfKey, aUuid), "New Model Creation", true)
	if ok {
		context.JSON(http.StatusCreated, gin.H{
			"message": "model created",
			"id":      aUuid,
		})
	}
}

func listModels(context *gin.Context) { // TODO currently returns error when any model is no longer valid in syntax, so eventually have some fallback to not just bark on an invalid model...
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)

	result := make([]payloadModels, 0)
	modelFolders, err := os.ReadDir(folderNameOfKey)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	for _, dirEntry := range modelFolders {
		if dirEntry.IsDir() {
			modelStat, err := os.Stat(folderNameOfKey + "/" + dirEntry.Name() + "/threagile.yaml")
			if err != nil {
				log.Println(err)
				context.JSON(http.StatusNotFound, gin.H{
					"error": "unable to list model",
				})
				return
			}
			aModel, _, ok := readModel(context, dirEntry.Name(), key, folderNameOfKey)
			if !ok {
				return
			}
			fileInfo, err := dirEntry.Info()
			if err != nil {
				log.Println(err)
				context.JSON(http.StatusNotFound, gin.H{
					"error": "unable to get file info",
				})
				return
			}
			result = append(result, payloadModels{
				ID:                dirEntry.Name(),
				Title:             aModel.Title,
				TimestampCreated:  fileInfo.ModTime(),
				TimestampModified: modelStat.ModTime(),
			})
		}
	}
	context.JSON(http.StatusOK, result)
}

func deleteModel(context *gin.Context) {
	folderNameOfKey, _, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	folder, ok := checkModelFolder(context, context.Param("model-id"), folderNameOfKey)
	if ok {
		err := os.RemoveAll(folder)
		if err != nil {
			context.JSON(http.StatusNotFound, gin.H{
				"error": "model not found",
			})
		}
		context.JSON(http.StatusOK, gin.H{
			"message": "model deleted",
		})
	}
}

func checkModelFolder(context *gin.Context, modelUUID string, folderNameOfKey string) (modelFolder string, ok bool) {
	uuidParsed, err := uuid.Parse(modelUUID)
	if err != nil {
		context.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	modelFolder = folderNameForModel(folderNameOfKey, uuidParsed.String())
	if _, err := os.Stat(modelFolder); os.IsNotExist(err) {
		context.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	return modelFolder, true
}

func readModel(context *gin.Context, modelUUID string, key []byte, folderNameOfKey string) (modelInputResult model.ModelInput, yamlText string, ok bool) {
	modelFolder, ok := checkModelFolder(context, modelUUID, folderNameOfKey)
	if !ok {
		return modelInputResult, yamlText, false
	}
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	fileBytes, err := os.ReadFile(modelFolder + "/threagile.yaml")
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	nonce := fileBytes[0:12]
	ciphertext := fileBytes[12:]
	plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	r, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	modelInput := model.ModelInput{}
	yamlBytes := buf.Bytes()
	err = yaml.Unmarshal(yamlBytes, &modelInput)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	return modelInput, string(yamlBytes), true
}

func writeModel(context *gin.Context, key []byte, folderNameOfKey string, modelInput *model.ModelInput, changeReasonForHistory string) (ok bool) {
	modelFolder, ok := checkModelFolder(context, context.Param("model-id"), folderNameOfKey)
	if ok {
		modelInput.ThreagileVersion = model.ThreagileVersion
		yamlBytes, err := yaml.Marshal(modelInput)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
		/*
			yamlBytes = model.ReformatYAML(yamlBytes)
		*/
		return writeModelYAML(context, string(yamlBytes), key, modelFolder, changeReasonForHistory, false)
	}
	return false
}

func writeModelYAML(context *gin.Context, yaml string, key []byte, modelFolder string, changeReasonForHistory string, skipBackup bool) (ok bool) {
	if *verbose {
		fmt.Println("about to write " + strconv.Itoa(len(yaml)) + " bytes of yaml into model folder: " + modelFolder)
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(yaml))
	_ = w.Close()
	plaintext := b.Bytes()
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	ciphertext := aesGcm.Seal(nil, nonce, plaintext, nil)
	if !skipBackup {
		err = backupModelToHistory(modelFolder, changeReasonForHistory)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
	}
	f, err := os.Create(modelFolder + "/threagile.yaml")
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	_, _ = f.Write(nonce)
	_, _ = f.Write(ciphertext)
	_ = f.Close()
	return true
}

func backupModelToHistory(modelFolder string, changeReasonForHistory string) (err error) {
	historyFolder := modelFolder + "/history"
	if _, err := os.Stat(historyFolder); os.IsNotExist(err) {
		err = os.Mkdir(historyFolder, 0700)
		if err != nil {
			return err
		}
	}
	input, err := os.ReadFile(modelFolder + "/threagile.yaml")
	if err != nil {
		return err
	}
	historyFile := historyFolder + "/" + time.Now().Format("2006-01-02 15:04:05") + " " + changeReasonForHistory + ".backup"
	err = os.WriteFile(historyFile, input, 0400)
	if err != nil {
		return err
	}
	// now delete any old files if over limit to keep
	files, err := os.ReadDir(historyFolder)
	if err != nil {
		return err
	}
	if len(files) > backupHistoryFilesToKeep {
		requiredToDelete := len(files) - backupHistoryFilesToKeep
		sort.Slice(files, func(i, j int) bool {
			return files[i].Name() < files[j].Name()
		})
		for _, file := range files {
			requiredToDelete--
			err = os.Remove(historyFolder + "/" + file.Name())
			if err != nil {
				return err
			}
			if requiredToDelete <= 0 {
				break
			}
		}
	}
	return
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func generateKeyFromAlreadyStrongRandomInput(alreadyRandomInput []byte) []byte {
	// Establish the parameters to use for Argon2.
	p := &argon2Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   keySize,
	}
	// As the input is already cryptographically secure random, the salt is simply the first n bytes
	salt := alreadyRandomInput[0:p.saltLength]
	hash := argon2.IDKey(alreadyRandomInput[p.saltLength:], salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash
}

func folderNameForModel(folderNameOfKey string, uuid string) string {
	return folderNameOfKey + "/" + uuid
}

var throttlerLock sync.Mutex
var createdObjectsThrottler = make(map[string][]int64)

func checkObjectCreationThrottler(context *gin.Context, typeName string) bool {
	throttlerLock.Lock()
	defer throttlerLock.Unlock()

	// remove all elements older than 3 minutes (= 180000000000 ns)
	now := time.Now().UnixNano()
	cutoff := now - 180000000000
	for keyCheck := range createdObjectsThrottler {
		for i := 0; i < len(createdObjectsThrottler[keyCheck]); i++ {
			if createdObjectsThrottler[keyCheck][i] < cutoff {
				// Remove the element at index i from slice (safe while looping using i as iterator)
				createdObjectsThrottler[keyCheck] = append(createdObjectsThrottler[keyCheck][:i], createdObjectsThrottler[keyCheck][i+1:]...)
				i-- // Since we just deleted a[i], we must redo that index
			}
		}
		length := len(createdObjectsThrottler[keyCheck])
		if length == 0 {
			delete(createdObjectsThrottler, keyCheck)
		}
		/*
			if *verbose {
				log.Println("Throttling count: "+strconv.Itoa(length))
			}
		*/
	}

	// check current request
	keyHash := hash(typeName) // getting the real client ip is not easy inside fully encapsulated containerized runtime
	if _, ok := createdObjectsThrottler[keyHash]; !ok {
		createdObjectsThrottler[keyHash] = make([]int64, 0)
	}
	// check the limit of 20 creations for this type per 3 minutes
	withinLimit := len(createdObjectsThrottler[keyHash]) < 20
	if withinLimit {
		createdObjectsThrottler[keyHash] = append(createdObjectsThrottler[keyHash], now)
		return true
	}
	context.JSON(http.StatusTooManyRequests, gin.H{
		"error": "object creation throttling exceeded (denial-of-service protection): please wait some time and try again",
	})
	return false
}

var locksByFolderName = make(map[string]*sync.Mutex)

func lockFolder(folderName string) {
	globalLock.Lock()
	defer globalLock.Unlock()
	_, exists := locksByFolderName[folderName]
	if !exists {
		locksByFolderName[folderName] = &sync.Mutex{}
	}
	locksByFolderName[folderName].Lock()
}

func unlockFolder(folderName string) {
	if _, exists := locksByFolderName[folderName]; exists {
		locksByFolderName[folderName].Unlock()
		delete(locksByFolderName, folderName)
	}
}

type tokenHeader struct {
	Token string `header:"token"`
}
type keyHeader struct {
	Key string `header:"key"`
}

func folderNameFromKey(key []byte) string {
	sha512Hash := hashSHA256(key)
	return baseFolder + "/" + sha512Hash
}

func hashSHA256(key []byte) string {
	hasher := sha512.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

func createKey(context *gin.Context) {
	ok := checkObjectCreationThrottler(context, "KEY")
	if !ok {
		return
	}
	globalLock.Lock()
	defer globalLock.Unlock()

	keyBytesArr := make([]byte, keySize)
	n, err := rand.Read(keyBytesArr[:])
	if n != keySize || err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create key",
		})
		return
	}
	err = os.Mkdir(folderNameFromKey(keyBytesArr), 0700)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create key",
		})
		return
	}
	context.JSON(http.StatusCreated, gin.H{
		"key": base64.RawURLEncoding.EncodeToString(keyBytesArr[:]),
	})
}

func checkTokenToFolderName(context *gin.Context) (folderNameOfKey string, key []byte, ok bool) {
	header := tokenHeader{}
	if err := context.ShouldBindHeader(&header); err != nil {
		log.Println(err)
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Token))
	if len(token) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
	globalLock.Lock()
	defer globalLock.Unlock()
	housekeepingTokenMaps() // to remove timed-out ones
	tokenHash := hashSHA256(token)
	if timeoutStruct, exists := mapTokenHashToTimeoutStruct[tokenHash]; exists {
		// re-create the key from token
		key := xor(token, timeoutStruct.xorRand)
		folderNameOfKey := folderNameFromKey(key)
		if _, err := os.Stat(folderNameOfKey); os.IsNotExist(err) {
			log.Println(err)
			context.JSON(http.StatusNotFound, gin.H{
				"error": "token not found",
			})
			return folderNameOfKey, key, false
		}
		timeoutStruct.lastAccessedNanoTime = time.Now().UnixNano()
		return folderNameOfKey, key, true
	} else {
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
}

func checkKeyToFolderName(context *gin.Context) (folderNameOfKey string, key []byte, ok bool) {
	header := keyHeader{}
	if err := context.ShouldBindHeader(&header); err != nil {
		log.Println(err)
		context.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Key))
	if len(key) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	folderNameOfKey = folderNameFromKey(key)
	if _, err := os.Stat(folderNameOfKey); os.IsNotExist(err) {
		log.Println(err)
		context.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	return folderNameOfKey, key, true
}

func deleteKey(context *gin.Context) {
	folderName, _, ok := checkKeyToFolderName(context)
	if !ok {
		return
	}
	globalLock.Lock()
	defer globalLock.Unlock()
	err := os.RemoveAll(folderName)
	if err != nil {
		log.Println("error during key delete: " + err.Error())
		context.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"message": "key deleted",
	})
}

func parseCommandlineArgs() {
	modelFilename = flag.String("model", "threagile.yaml", "input model yaml file")
	outputDir = flag.String("output", ".", "output directory")
	raaPlugin = flag.String("raa-plugin", "raa.so", "RAA calculation plugin (.so shared object) file name")
	executeModelMacro = flag.String("execute-model-macro", "", "Execute model macro (by ID)")
	createExampleModel = flag.Bool("create-example-model", false, "just create an example model named threagile-example-model.yaml in the output directory")
	createStubModel = flag.Bool("create-stub-model", false, "just create a minimal stub model named threagile-stub-model.yaml in the output directory")
	createEditingSupport = flag.Bool("create-editing-support", false, "just create some editing support stuff in the output directory")
	serverPort = flag.Int("server", 0, "start a server (instead of commandline execution) on the given port")
	templateFilename = flag.String("background", "background.pdf", "background pdf file")
	generateDataFlowDiagram = flag.Bool("generate-data-flow-diagram", true, "generate data-flow diagram")
	generateDataAssetDiagram = flag.Bool("generate-data-asset-diagram", true, "generate data asset diagram")
	generateRisksJSON = flag.Bool("generate-risks-json", true, "generate risks json")
	generateTechnicalAssetsJSON = flag.Bool("generate-technical-assets-json", true, "generate technical assets json")
	generateStatsJSON = flag.Bool("generate-stats-json", true, "generate stats json")
	generateRisksExcel = flag.Bool("generate-risks-excel", true, "generate risks excel")
	generateTagsExcel = flag.Bool("generate-tags-excel", true, "generate tags excel")
	generateReportPDF = flag.Bool("generate-report-pdf", true, "generate report pdf, including diagrams")
	diagramDPI = flag.Int("diagram-dpi", defaultGraphvizDPI, "DPI used to render: maximum is "+strconv.Itoa(maxGraphvizDPI)+"")
	skipRiskRules = flag.String("skip-risk-rules", "", "comma-separated list of risk rules (by their ID) to skip")
	riskRulesPlugins = flag.String("custom-risk-rules-plugins", "", "comma-separated list of plugins (.so shared object) file names with custom risk rules to load")
	verbose = flag.Bool("verbose", false, "verbose output")
	ignoreOrphanedRiskTracking = flag.Bool("ignore-orphaned-risk-tracking", false, "ignore orphaned risk tracking (just log them) not matching a concrete risk")
	version := flag.Bool("version", false, "print version")
	listTypes := flag.Bool("list-types", false, "print type information (enum values to be used in models)")
	listRiskRules := flag.Bool("list-risk-rules", false, "print risk rules")
	listModelMacros := flag.Bool("list-model-macros", false, "print model macros")
	explainTypes := flag.Bool("explain-types", false, "Detailed explanation of all the types")
	explainRiskRules := flag.Bool("explain-risk-rules", false, "Detailed explanation of all the risk rules")
	explainModelMacros := flag.Bool("explain-model-macros", false, "Detailed explanation of all the model macros")
	print3rdParty := flag.Bool("print-3rd-party-licenses", false, "print 3rd-party license information")
	license := flag.Bool("print-license", false, "print license information")
	flag.Usage = func() {
		printLogo()
		_, _ = fmt.Fprintf(os.Stderr, "Usage: threagile [options]")
		fmt.Println()
		fmt.Println()
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println()
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println()
		fmt.Println("If you want to create an example model (via docker) as a starting point to learn about Threagile just run: ")
		fmt.Println(" docker run --rm -it " +
			"-v \"$(pwd)\":/app/work " +
			"threagile/threagile " +
			"-create-example-model " +
			"-output /app/work")
		fmt.Println()
		fmt.Println("If you want to create a minimal stub model (via docker) as a starting point for your own model just run: ")
		fmt.Println(" docker run --rm -it " +
			"-v \"$(pwd)\":/app/work " +
			"threagile/threagile " +
			"-create-stub-model " +
			"-output /app/work")
		fmt.Println()
		printExamples()
		fmt.Println()
	}
	flag.Parse()
	if *diagramDPI < 20 {
		*diagramDPI = 20
	} else if *diagramDPI > maxGraphvizDPI {
		*diagramDPI = 300
	}
	if *version {
		printLogo()
		os.Exit(0)
	}
	if *listTypes {
		printLogo()
		fmt.Println("The following types are available (can be extended for custom rules):")
		fmt.Println()
		printTypes("Authentication", model.AuthenticationValues())
		fmt.Println()
		printTypes("Authorization", model.AuthorizationValues())
		fmt.Println()
		printTypes("Confidentiality", model.ConfidentialityValues())
		fmt.Println()
		printTypes("Criticality (for integrity and availability)", model.CriticalityValues())
		fmt.Println()
		printTypes("Data Breach Probability", model.DataBreachProbabilityValues())
		fmt.Println()
		printTypes("Data Format", model.DataFormatValues())
		fmt.Println()
		printTypes("Encryption", model.EncryptionStyleValues())
		fmt.Println()
		printTypes("Protocol", model.ProtocolValues())
		fmt.Println()
		printTypes("Quantity", model.QuantityValues())
		fmt.Println()
		printTypes("Risk Exploitation Impact", model.RiskExploitationImpactValues())
		fmt.Println()
		printTypes("Risk Exploitation Likelihood", model.RiskExploitationLikelihoodValues())
		fmt.Println()
		printTypes("Risk Function", model.RiskFunctionValues())
		fmt.Println()
		printTypes("Risk Severity", model.RiskSeverityValues())
		fmt.Println()
		printTypes("Risk Status", model.RiskStatusValues())
		fmt.Println()
		printTypes("STRIDE", model.STRIDEValues())
		fmt.Println()
		printTypes("Technical Asset Machine", model.TechnicalAssetMachineValues())
		fmt.Println()
		printTypes("Technical Asset Size", model.TechnicalAssetSizeValues())
		fmt.Println()
		printTypes("Technical Asset Technology", model.TechnicalAssetTechnologyValues())
		fmt.Println()
		printTypes("Technical Asset Type", model.TechnicalAssetTypeValues())
		fmt.Println()
		printTypes("Trust Boundary Type", model.TrustBoundaryTypeValues())
		fmt.Println()
		printTypes("Usage", model.UsageValues())
		fmt.Println()
		os.Exit(0)
	}
	if *listModelMacros {
		printLogo()
		fmt.Println("The following model macros are available (can be extended via custom model macros):")
		fmt.Println()
		/* TODO finish plugin stuff
		fmt.Println("Custom model macros:")
		for id, customModelMacro := range customModelMacros {
			fmt.Println(id, "-->", customModelMacro.GetMacroDetails().Title)
		}
		fmt.Println()
		*/
		fmt.Println("----------------------")
		fmt.Println("Built-in model macros:")
		fmt.Println("----------------------")
		fmt.Println(addbuildpipeline.GetMacroDetails().ID, "-->", addbuildpipeline.GetMacroDetails().Title)
		fmt.Println(addvault.GetMacroDetails().ID, "-->", addvault.GetMacroDetails().Title)
		fmt.Println(prettyprint.GetMacroDetails().ID, "-->", prettyprint.GetMacroDetails().Title)
		fmt.Println(removeunusedtags.GetMacroDetails().ID, "-->", removeunusedtags.GetMacroDetails().Title)
		fmt.Println(seedrisktracking.GetMacroDetails().ID, "-->", seedrisktracking.GetMacroDetails().Title)
		fmt.Println(seedtags.GetMacroDetails().ID, "-->", seedtags.GetMacroDetails().Title)
		fmt.Println()
		os.Exit(0)
	}
	if *listRiskRules {
		printLogo()
		fmt.Println("The following risk rules are available (can be extended via custom risk rules):")
		fmt.Println()
		fmt.Println("------------------")
		fmt.Println("Custom risk rules:")
		fmt.Println("------------------")
		loadCustomRiskRules()
		for id, customRule := range customRiskRules {
			fmt.Println(id, "-->", customRule.Category().Title, "--> with tags:", customRule.SupportedTags())
		}
		fmt.Println()
		fmt.Println("--------------------")
		fmt.Println("Built-in risk rules:")
		fmt.Println("--------------------")
		fmt.Println(accidentalsecretleak.Category().Id, "-->", accidentalsecretleak.Category().Title, "--> with tags:", accidentalsecretleak.SupportedTags())
		fmt.Println(codebackdooring.Category().Id, "-->", codebackdooring.Category().Title, "--> with tags:", codebackdooring.SupportedTags())
		fmt.Println(containerbaseimagebackdooring.Category().Id, "-->", containerbaseimagebackdooring.Category().Title, "--> with tags:", containerbaseimagebackdooring.SupportedTags())
		fmt.Println(containerplatformescape.Category().Id, "-->", containerplatformescape.Category().Title, "--> with tags:", containerplatformescape.SupportedTags())
		fmt.Println(crosssiterequestforgery.Category().Id, "-->", crosssiterequestforgery.Category().Title, "--> with tags:", crosssiterequestforgery.SupportedTags())
		fmt.Println(crosssitescripting.Category().Id, "-->", crosssitescripting.Category().Title, "--> with tags:", crosssitescripting.SupportedTags())
		fmt.Println(dosriskyaccessacrosstrustboundary.Category().Id, "-->", dosriskyaccessacrosstrustboundary.Category().Title, "--> with tags:", dosriskyaccessacrosstrustboundary.SupportedTags())
		fmt.Println(incompletemodel.Category().Id, "-->", incompletemodel.Category().Title, "--> with tags:", incompletemodel.SupportedTags())
		fmt.Println(ldapinjection.Category().Id, "-->", ldapinjection.Category().Title, "--> with tags:", ldapinjection.SupportedTags())
		fmt.Println(missingauthentication.Category().Id, "-->", missingauthentication.Category().Title, "--> with tags:", missingauthentication.SupportedTags())
		fmt.Println(missingauthenticationsecondfactor.Category().Id, "-->", missingauthenticationsecondfactor.Category().Title, "--> with tags:", missingauthenticationsecondfactor.SupportedTags())
		fmt.Println(missingbuildinfrastructure.Category().Id, "-->", missingbuildinfrastructure.Category().Title, "--> with tags:", missingbuildinfrastructure.SupportedTags())
		fmt.Println(missingcloudhardening.Category().Id, "-->", missingcloudhardening.Category().Title, "--> with tags:", missingcloudhardening.SupportedTags())
		fmt.Println(missingfilevalidation.Category().Id, "-->", missingfilevalidation.Category().Title, "--> with tags:", missingfilevalidation.SupportedTags())
		fmt.Println(missinghardening.Category().Id, "-->", missinghardening.Category().Title, "--> with tags:", missinghardening.SupportedTags())
		fmt.Println(missingidentitypropagation.Category().Id, "-->", missingidentitypropagation.Category().Title, "--> with tags:", missingidentitypropagation.SupportedTags())
		fmt.Println(missingidentityproviderisolation.Category().Id, "-->", missingidentityproviderisolation.Category().Title, "--> with tags:", missingidentityproviderisolation.SupportedTags())
		fmt.Println(missingidentitystore.Category().Id, "-->", missingidentitystore.Category().Title, "--> with tags:", missingidentitystore.SupportedTags())
		fmt.Println(missingnetworksegmentation.Category().Id, "-->", missingnetworksegmentation.Category().Title, "--> with tags:", missingnetworksegmentation.SupportedTags())
		fmt.Println(missingvault.Category().Id, "-->", missingvault.Category().Title, "--> with tags:", missingvault.SupportedTags())
		fmt.Println(missingvaultisolation.Category().Id, "-->", missingvaultisolation.Category().Title, "--> with tags:", missingvaultisolation.SupportedTags())
		fmt.Println(missingwaf.Category().Id, "-->", missingwaf.Category().Title, "--> with tags:", missingwaf.SupportedTags())
		fmt.Println(mixedtargetsonsharedruntime.Category().Id, "-->", mixedtargetsonsharedruntime.Category().Title, "--> with tags:", mixedtargetsonsharedruntime.SupportedTags())
		fmt.Println(pathtraversal.Category().Id, "-->", pathtraversal.Category().Title, "--> with tags:", pathtraversal.SupportedTags())
		fmt.Println(pushinsteadofpulldeployment.Category().Id, "-->", pushinsteadofpulldeployment.Category().Title, "--> with tags:", pushinsteadofpulldeployment.SupportedTags())
		fmt.Println(searchqueryinjection.Category().Id, "-->", searchqueryinjection.Category().Title, "--> with tags:", searchqueryinjection.SupportedTags())
		fmt.Println(serversiderequestforgery.Category().Id, "-->", serversiderequestforgery.Category().Title, "--> with tags:", serversiderequestforgery.SupportedTags())
		fmt.Println(serviceregistrypoisoning.Category().Id, "-->", serviceregistrypoisoning.Category().Title, "--> with tags:", serviceregistrypoisoning.SupportedTags())
		fmt.Println(sqlnosqlinjection.Category().Id, "-->", sqlnosqlinjection.Category().Title, "--> with tags:", sqlnosqlinjection.SupportedTags())
		fmt.Println(uncheckeddeployment.Category().Id, "-->", uncheckeddeployment.Category().Title, "--> with tags:", uncheckeddeployment.SupportedTags())
		fmt.Println(unencryptedasset.Category().Id, "-->", unencryptedasset.Category().Title, "--> with tags:", unencryptedasset.SupportedTags())
		fmt.Println(unencryptedcommunication.Category().Id, "-->", unencryptedcommunication.Category().Title, "--> with tags:", unencryptedcommunication.SupportedTags())
		fmt.Println(unguardedaccessfrominternet.Category().Id, "-->", unguardedaccessfrominternet.Category().Title, "--> with tags:", unguardedaccessfrominternet.SupportedTags())
		fmt.Println(unguardeddirectdatastoreaccess.Category().Id, "-->", unguardeddirectdatastoreaccess.Category().Title, "--> with tags:", unguardeddirectdatastoreaccess.SupportedTags())
		fmt.Println(unnecessarycommunicationlink.Category().Id, "-->", unnecessarycommunicationlink.Category().Title, "--> with tags:", unnecessarycommunicationlink.SupportedTags())
		fmt.Println(unnecessarydataasset.Category().Id, "-->", unnecessarydataasset.Category().Title, "--> with tags:", unnecessarydataasset.SupportedTags())
		fmt.Println(unnecessarydatatransfer.Category().Id, "-->", unnecessarydatatransfer.Category().Title, "--> with tags:", unnecessarydatatransfer.SupportedTags())
		fmt.Println(unnecessarytechnicalasset.Category().Id, "-->", unnecessarytechnicalasset.Category().Title, "--> with tags:", unnecessarytechnicalasset.SupportedTags())
		fmt.Println(untrusteddeserialization.Category().Id, "-->", untrusteddeserialization.Category().Title, "--> with tags:", untrusteddeserialization.SupportedTags())
		fmt.Println(wrongcommunicationlinkcontent.Category().Id, "-->", wrongcommunicationlinkcontent.Category().Title, "--> with tags:", wrongcommunicationlinkcontent.SupportedTags())
		fmt.Println(wrongtrustboundarycontent.Category().Id, "-->", wrongtrustboundarycontent.Category().Title, "--> with tags:", wrongtrustboundarycontent.SupportedTags())
		fmt.Println(xmlexternalentity.Category().Id, "-->", xmlexternalentity.Category().Title, "--> with tags:", xmlexternalentity.SupportedTags())
		fmt.Println()
		os.Exit(0)
	}
	if *explainTypes {
		printLogo()
		fmt.Println("Explanation for the types:")
		fmt.Println()
		printExplainTypes("Authentication", model.AuthenticationValues())
		printExplainTypes("Authorization", model.AuthorizationValues())
		printExplainTypes("Confidentiality", model.ConfidentialityValues())
		printExplainTypes("Criticality", model.CriticalityValues())
		printExplainTypes("Data Breach Probability", model.DataBreachProbabilityValues())
		printExplainTypes("Data Format", model.DataFormatValues())
		printExplainTypes("Encryption", model.EncryptionStyleValues())
		printExplainTypes("Protocol", model.ProtocolValues())
		printExplainTypes("Quantity", model.QuantityValues())
		printExplainTypes("Risk Exploitation Impact", model.RiskExploitationImpactValues())
		printExplainTypes("Risk Exploitation likelihood", model.RiskExploitationLikelihoodValues())
		printExplainTypes("Risk Function", model.RiskFunctionValues())
		printExplainTypes("Risk Severity", model.RiskSeverityValues())
		printExplainTypes("Risk Status", model.RiskStatusValues())
		printExplainTypes("STRIDE", model.STRIDEValues())
		printExplainTypes("Technical Asset Machine", model.TechnicalAssetMachineValues())
		printExplainTypes("Technical Asset Size", model.TechnicalAssetSizeValues())
		printExplainTypes("Technical Asset Technology", model.TechnicalAssetTechnologyValues())
		printExplainTypes("Technical Asset Type", model.TechnicalAssetTypeValues())
		printExplainTypes("Trust Boundary Type", model.TrustBoundaryTypeValues())
		printExplainTypes("Usage", model.UsageValues())

		os.Exit(0)
	}
	if *explainModelMacros {
		printLogo()
		fmt.Println("Explanation for the model macros:")
		fmt.Println()
		fmt.Printf("%v: %v\n", addbuildpipeline.GetMacroDetails().ID, addbuildpipeline.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", addvault.GetMacroDetails().ID, addvault.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", prettyprint.GetMacroDetails().ID, prettyprint.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", removeunusedtags.GetMacroDetails().ID, removeunusedtags.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", seedrisktracking.GetMacroDetails().ID, seedrisktracking.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", seedtags.GetMacroDetails().ID, seedtags.GetMacroDetails().Description)
		fmt.Println()
		os.Exit(0)

	}
	if *explainRiskRules {
		printLogo()
		fmt.Println("Explanation for risk rules:")
		fmt.Println()
		fmt.Printf("%v: %v\n", accidentalsecretleak.Category().Id, accidentalsecretleak.Category().Description)
		fmt.Printf("%v: %v\n", codebackdooring.Category().Id, codebackdooring.Category().Description)
		fmt.Printf("%v: %v\n", containerbaseimagebackdooring.Category().Id, containerbaseimagebackdooring.Category().Description)
		fmt.Printf("%v: %v\n", containerplatformescape.Category().Id, containerplatformescape.Category().Description)
		fmt.Printf("%v: %v\n", crosssiterequestforgery.Category().Id, crosssiterequestforgery.Category().Description)
		fmt.Printf("%v: %v\n", crosssitescripting.Category().Id, crosssitescripting.Category().Description)
		fmt.Printf("%v: %v\n", dosriskyaccessacrosstrustboundary.Category().Id, dosriskyaccessacrosstrustboundary.Category().Description)
		fmt.Printf("%v: %v\n", incompletemodel.Category().Id, incompletemodel.Category().Description)
		fmt.Printf("%v: %v\n", ldapinjection.Category().Id, ldapinjection.Category().Description)
		fmt.Printf("%v: %v\n", missingauthentication.Category().Id, missingauthentication.Category().Description)
		fmt.Printf("%v: %v\n", missingauthenticationsecondfactor.Category().Id, missingauthenticationsecondfactor.Category().Description)
		fmt.Printf("%v: %v\n", missingbuildinfrastructure.Category().Id, missingbuildinfrastructure.Category().Description)
		fmt.Printf("%v: %v\n", missingcloudhardening.Category().Id, missingcloudhardening.Category().Description)
		fmt.Printf("%v: %v\n", missingfilevalidation.Category().Id, missingfilevalidation.Category().Description)
		fmt.Printf("%v: %v\n", missinghardening.Category().Id, missinghardening.Category().Description)
		fmt.Printf("%v: %v\n", missingidentitypropagation.Category().Id, missingidentitypropagation.Category().Description)
		fmt.Printf("%v: %v\n", missingidentityproviderisolation.Category().Id, missingidentityproviderisolation.Category().Description)
		fmt.Printf("%v: %v\n", missingidentitystore.Category().Id, missingidentitystore.Category().Description)
		fmt.Printf("%v: %v\n", missingnetworksegmentation.Category().Id, missingnetworksegmentation.Category().Description)
		fmt.Printf("%v: %v\n", missingvault.Category().Id, missingvault.Category().Description)
		fmt.Printf("%v: %v\n", missingvaultisolation.Category().Id, missingvaultisolation.Category().Description)
		fmt.Printf("%v: %v\n", missingwaf.Category().Id, missingwaf.Category().Description)
		fmt.Printf("%v: %v\n", mixedtargetsonsharedruntime.Category().Id, mixedtargetsonsharedruntime.Category().Description)
		fmt.Printf("%v: %v\n", pathtraversal.Category().Id, pathtraversal.Category().Description)
		fmt.Printf("%v: %v\n", pushinsteadofpulldeployment.Category().Id, pushinsteadofpulldeployment.Category().Description)
		fmt.Printf("%v: %v\n", searchqueryinjection.Category().Id, searchqueryinjection.Category().Description)
		fmt.Printf("%v: %v\n", serversiderequestforgery.Category().Id, serversiderequestforgery.Category().Description)
		fmt.Printf("%v: %v\n", serviceregistrypoisoning.Category().Id, serviceregistrypoisoning.Category().Description)
		fmt.Printf("%v: %v\n", sqlnosqlinjection.Category().Id, sqlnosqlinjection.Category().Description)
		fmt.Printf("%v: %v\n", uncheckeddeployment.Category().Id, uncheckeddeployment.Category().Description)
		fmt.Printf("%v: %v\n", unencryptedasset.Category().Id, unencryptedasset.Category().Description)
		fmt.Printf("%v: %v\n", unencryptedcommunication.Category().Id, unencryptedcommunication.Category().Description)
		fmt.Printf("%v: %v\n", unguardedaccessfrominternet.Category().Id, unguardedaccessfrominternet.Category().Description)
		fmt.Printf("%v: %v\n", unguardeddirectdatastoreaccess.Category().Id, unguardeddirectdatastoreaccess.Category().Description)
		fmt.Printf("%v: %v\n", unnecessarycommunicationlink.Category().Id, unnecessarycommunicationlink.Category().Description)
		fmt.Printf("%v: %v\n", unnecessarydataasset.Category().Id, unnecessarydataasset.Category().Description)
		fmt.Printf("%v: %v\n", unnecessarydatatransfer.Category().Id, unnecessarydatatransfer.Category().Description)
		fmt.Printf("%v: %v\n", unnecessarytechnicalasset.Category().Id, unnecessarytechnicalasset.Category().Description)
		fmt.Printf("%v: %v\n", untrusteddeserialization.Category().Id, untrusteddeserialization.Category().Description)
		fmt.Printf("%v: %v\n", wrongcommunicationlinkcontent.Category().Id, wrongcommunicationlinkcontent.Category().Description)
		fmt.Printf("%v: %v\n", wrongtrustboundarycontent.Category().Id, wrongtrustboundarycontent.Category().Description)
		fmt.Printf("%v: %v\n", xmlexternalentity.Category().Id, xmlexternalentity.Category().Description)
		fmt.Println()
		os.Exit(0)
	}
	if *print3rdParty {
		printLogo()
		fmt.Println("Kudos & Credits to the following open-source projects:")
		fmt.Println(" - golang (Google Go License): https://golang.org/LICENSE")
		fmt.Println(" - go-yaml (MIT License): https://github.com/go-yaml/yaml/blob/v3/LICENSE")
		fmt.Println(" - graphviz (CPL License): https://graphviz.gitlab.io/license/")
		fmt.Println(" - gofpdf (MIT License): https://github.com/jung-kurt/gofpdf/blob/master/LICENSE")
		fmt.Println(" - go-chart (MIT License): https://github.com/wcharczuk/go-chart/blob/master/LICENSE")
		fmt.Println(" - excelize (BSD License): https://github.com/qax-os/excelize/blob/master/LICENSE")
		fmt.Println(" - graphics-go (BSD License): https://github.com/BurntSushi/graphics-go/blob/master/LICENSE")
		fmt.Println(" - google-uuid (BSD License): https://github.com/google/uuid/blob/master/LICENSE")
		fmt.Println(" - gin-gonic (MIT License): https://github.com/gin-gonic/gin/blob/master/LICENSE")
		fmt.Println(" - swagger-ui (Apache License): https://swagger.io/license/")
		fmt.Println()
		os.Exit(0)
	}
	if *license {
		printLogo()
		content, err := os.ReadFile("/app/LICENSE.txt")
		checkErr(err)
		fmt.Print(string(content))
		fmt.Println()
		os.Exit(0)
	}
	if *createExampleModel {
		createExampleModelFile()
		printLogo()
		fmt.Println("An example model was created named threagile-example-model.yaml in the output directory.")
		fmt.Println()
		printExamples()
		fmt.Println()
		os.Exit(0)
	}
	if *createStubModel {
		createStubModelFile()
		printLogo()
		fmt.Println("A minimal stub model was created named threagile-stub-model.yaml in the output directory.")
		fmt.Println()
		printExamples()
		fmt.Println()
		os.Exit(0)
	}
	if *createEditingSupport {
		createEditingSupportFiles()
		printLogo()
		fmt.Println("The following files were created in the output directory:")
		fmt.Println(" - schema.json")
		fmt.Println(" - live-templates.txt")
		fmt.Println()
		fmt.Println("For a perfect editing experience within your IDE of choice you can easily get " +
			"model syntax validation and autocompletion (very handy for enum values) as well as live templates: " +
			"Just import the schema.json into your IDE and assign it as \"schema\" to each Threagile YAML file. " +
			"Also try to import individual parts from the live-templates.txt file into your IDE as live editing templates.")
		fmt.Println()
		os.Exit(0)
	}
}

func printLogo() {
	fmt.Println()
	fmt.Println("  _____ _                          _ _      \n |_   _| |__  _ __ ___  __ _  __ _(_) | ___ \n   | | | '_ \\| '__/ _ \\/ _` |/ _` | | |/ _ \\\n   | | | | | | | |  __/ (_| | (_| | | |  __/\n   |_| |_| |_|_|  \\___|\\__,_|\\__, |_|_|\\___|\n                             |___/        ")
	fmt.Println("Threagile - Agile Threat Modeling")
	fmt.Println()
	fmt.Println()
	printVersion()
}

func printVersion() {
	fmt.Println("Documentation: https://threagile.io")
	fmt.Println("Docker Images: https://hub.docker.com/r/threagile/threagile")
	fmt.Println("Sourcecode: https://github.com/threagile")
	fmt.Println("License: Open-Source (MIT License)")
	fmt.Println("Version: " + model.ThreagileVersion + " (" + buildTimestamp + ")")
	fmt.Println()
	fmt.Println()
}

func createExampleModelFile() {
	_, _ = copyFile("/app/threagile-example-model.yaml", *outputDir+"/threagile-example-model.yaml")
}

func createStubModelFile() {
	loadCustomRiskRules()
	stub, err := os.ReadFile("/app/threagile-stub-model.yaml")
	checkErr(err)
	err = os.WriteFile(*outputDir+"/threagile-stub-model.yaml", addSupportedTags(stub), 0644)
	checkErr(err)
}

func createEditingSupportFiles() {
	_, _ = copyFile("/app/schema.json", *outputDir+"/schema.json")
	_, _ = copyFile("/app/live-templates.txt", *outputDir+"/live-templates.txt")
}

func printExamples() {
	fmt.Println("If you want to execute Threagile on a model yaml file (via docker): ")
	fmt.Println(" docker run --rm -it " +
		"-v \"$(pwd)\":/app/work " +
		"threagile/threagile " +
		"-verbose " +
		"-model /app/work/threagile.yaml " +
		"-output /app/work")
	fmt.Println()
	fmt.Println("If you want to run Threagile as a server (REST API) on some port (here 8080): ")
	fmt.Println(" docker run --rm -it " +
		"--shm-size=256m " +
		"-p 8080:8080 " +
		"--name threagile-server " +
		"--mount 'type=volume,src=threagile-storage,dst=/data,readonly=false' " +
		"threagile/threagile -server 8080")
	fmt.Println()
	fmt.Println("If you want to find out about the different enum values usable in the model yaml file: ")
	fmt.Println(" docker run --rm -it threagile/threagile -list-types")
	fmt.Println()
	fmt.Println("If you want to use some nice editing help (syntax validation, autocompletion, and live templates) in your favourite IDE: ")
	fmt.Println(" docker run --rm -it -v \"$(pwd)\":/app/work threagile/threagile -create-editing-support -output /app/work")
	fmt.Println()
	fmt.Println("If you want to list all available model macros (which are macros capable of reading a model yaml file, asking you questions in a wizard-style and then update the model yaml file accordingly): ")
	fmt.Println(" docker run --rm -it threagile/threagile -list-model-macros")
	fmt.Println()
	fmt.Println("If you want to execute a certain model macro on the model yaml file (here the macro add-build-pipeline): ")
	fmt.Println(" docker run --rm -it -v \"$(pwd)\":/app/work threagile/threagile -model /app/work/threagile.yaml -output /app/work -execute-model-macro add-build-pipeline")
}

func printTypes(title string, value interface{}) {
	fmt.Println(fmt.Sprintf("  %v: %v", title, value))
}

// explainTypes prints and explanation block and a header
func printExplainTypes(title string, value []model.TypeEnum) {
	fmt.Println(title)
	for _, candidate := range value {
		fmt.Printf("\t %v: %v\n", candidate, candidate.Explain())
	}
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer func() { _ = source.Close() }()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer func() { _ = destination.Close() }()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func parseModel(inputFilename string) {
	if *verbose {
		fmt.Println("Parsing model:", inputFilename)
	}
	modelYaml, err := os.ReadFile(inputFilename)
	if err == nil {
		modelInput = model.ModelInput{}
		err = yaml.Unmarshal(modelYaml, &modelInput)
		checkErr(err)
		//fmt.Println(modelInput)

		var businessCriticality model.Criticality
		switch modelInput.BusinessCriticality {
		case model.Archive.String():
			businessCriticality = model.Archive
		case model.Operational.String():
			businessCriticality = model.Operational
		case model.Important.String():
			businessCriticality = model.Important
		case model.Critical.String():
			businessCriticality = model.Critical
		case model.MissionCritical.String():
			businessCriticality = model.MissionCritical
		default:
			panic(errors.New("unknown 'business_criticality' value of application: " + modelInput.BusinessCriticality))
		}

		reportDate := time.Now()
		if len(modelInput.Date) > 0 {
			reportDate, err = time.Parse("2006-01-02", modelInput.Date)
			if err != nil {
				panic(errors.New("unable to parse 'date' value of model file"))
			}
		}

		model.ParsedModelRoot = model.ParsedModel{
			Author:                         modelInput.Author,
			Title:                          modelInput.Title,
			Date:                           reportDate,
			ManagementSummaryComment:       modelInput.ManagementSummaryComment,
			BusinessCriticality:            businessCriticality,
			BusinessOverview:               removePathElementsFromImageFiles(modelInput.BusinessOverview),
			TechnicalOverview:              removePathElementsFromImageFiles(modelInput.TechnicalOverview),
			Questions:                      modelInput.Questions,
			AbuseCases:                     modelInput.AbuseCases,
			SecurityRequirements:           modelInput.SecurityRequirements,
			TagsAvailable:                  lowerCaseAndTrim(modelInput.TagsAvailable),
			DiagramTweakNodesep:            modelInput.DiagramTweakNodesep,
			DiagramTweakRanksep:            modelInput.DiagramTweakRanksep,
			DiagramTweakEdgeLayout:         modelInput.DiagramTweakEdgeLayout,
			DiagramTweakSuppressEdgeLabels: modelInput.DiagramTweakSuppressEdgeLabels,
			DiagramTweakLayoutLeftToRight:  modelInput.DiagramTweakLayoutLeftToRight,
			DiagramTweakInvisibleConnectionsBetweenAssets: modelInput.DiagramTweakInvisibleConnectionsBetweenAssets,
			DiagramTweakSameRankAssets:                    modelInput.DiagramTweakSameRankAssets,
		}
		if model.ParsedModelRoot.DiagramTweakNodesep == 0 {
			model.ParsedModelRoot.DiagramTweakNodesep = 2
		}
		if model.ParsedModelRoot.DiagramTweakRanksep == 0 {
			model.ParsedModelRoot.DiagramTweakRanksep = 2
		}

		// Data Assets ===============================================================================
		model.ParsedModelRoot.DataAssets = make(map[string]model.DataAsset)
		for title, asset := range modelInput.DataAssets {
			id := fmt.Sprintf("%v", asset.ID)

			var usage model.Usage
			switch asset.Usage {
			case model.Business.String():
				usage = model.Business
			case model.DevOps.String():
				usage = model.DevOps
			default:
				panic(errors.New("unknown 'usage' value of data asset '" + title + "': " + asset.Usage))
			}

			var quantity model.Quantity
			switch asset.Quantity {
			case model.VeryFew.String():
				quantity = model.VeryFew
			case model.Few.String():
				quantity = model.Few
			case model.Many.String():
				quantity = model.Many
			case model.VeryMany.String():
				quantity = model.VeryMany
			default:
				panic(errors.New("unknown 'quantity' value of data asset '" + title + "': " + asset.Quantity))
			}

			var confidentiality model.Confidentiality
			switch asset.Confidentiality {
			case model.Public.String():
				confidentiality = model.Public
			case model.Internal.String():
				confidentiality = model.Internal
			case model.Restricted.String():
				confidentiality = model.Restricted
			case model.Confidential.String():
				confidentiality = model.Confidential
			case model.StrictlyConfidential.String():
				confidentiality = model.StrictlyConfidential
			default:
				panic(errors.New("unknown 'confidentiality' value of data asset '" + title + "': " + asset.Confidentiality))
			}

			var integrity model.Criticality
			switch asset.Integrity {
			case model.Archive.String():
				integrity = model.Archive
			case model.Operational.String():
				integrity = model.Operational
			case model.Important.String():
				integrity = model.Important
			case model.Critical.String():
				integrity = model.Critical
			case model.MissionCritical.String():
				integrity = model.MissionCritical
			default:
				panic(errors.New("unknown 'integrity' value of data asset '" + title + "': " + asset.Integrity))
			}

			var availability model.Criticality
			switch asset.Availability {
			case model.Archive.String():
				availability = model.Archive
			case model.Operational.String():
				availability = model.Operational
			case model.Important.String():
				availability = model.Important
			case model.Critical.String():
				availability = model.Critical
			case model.MissionCritical.String():
				availability = model.MissionCritical
			default:
				panic(errors.New("unknown 'availability' value of data asset '" + title + "': " + asset.Availability))
			}

			checkIdSyntax(id)
			if _, exists := model.ParsedModelRoot.DataAssets[id]; exists {
				panic(errors.New("duplicate id used: " + id))
			}
			model.ParsedModelRoot.DataAssets[id] = model.DataAsset{
				Id:                     id,
				Title:                  title,
				Usage:                  usage,
				Description:            withDefault(fmt.Sprintf("%v", asset.Description), title),
				Quantity:               quantity,
				Tags:                   checkTags(lowerCaseAndTrim(asset.Tags), "data asset '"+title+"'"),
				Origin:                 fmt.Sprintf("%v", asset.Origin),
				Owner:                  fmt.Sprintf("%v", asset.Owner),
				Confidentiality:        confidentiality,
				Integrity:              integrity,
				Availability:           availability,
				JustificationCiaRating: fmt.Sprintf("%v", asset.JustificationCiaRating),
			}
		}

		// Technical Assets ===============================================================================
		model.ParsedModelRoot.TechnicalAssets = make(map[string]model.TechnicalAsset)
		for title, asset := range modelInput.TechnicalAssets {
			id := fmt.Sprintf("%v", asset.ID)

			var usage model.Usage
			switch asset.Usage {
			case model.Business.String():
				usage = model.Business
			case model.DevOps.String():
				usage = model.DevOps
			default:
				panic(errors.New("unknown 'usage' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Usage)))
			}

			var dataAssetsProcessed = make([]string, 0)
			if asset.DataAssetsProcessed != nil {
				dataAssetsProcessed = make([]string, len(asset.DataAssetsProcessed))
				for i, parsedProcessedAsset := range asset.DataAssetsProcessed {
					referencedAsset := fmt.Sprintf("%v", parsedProcessedAsset)
					checkDataAssetTargetExists(referencedAsset, "technical asset '"+title+"'")
					dataAssetsProcessed[i] = referencedAsset
				}
			}

			var dataAssetsStored = make([]string, 0)
			if asset.DataAssetsStored != nil {
				dataAssetsStored = make([]string, len(asset.DataAssetsStored))
				for i, parsedStoredAssets := range asset.DataAssetsStored {
					referencedAsset := fmt.Sprintf("%v", parsedStoredAssets)
					checkDataAssetTargetExists(referencedAsset, "technical asset '"+title+"'")
					dataAssetsStored[i] = referencedAsset
				}
			}

			var technicalAssetType model.TechnicalAssetType
			switch asset.Type {
			case model.ExternalEntity.String():
				technicalAssetType = model.ExternalEntity
			case model.Process.String():
				technicalAssetType = model.Process
			case model.Datastore.String():
				technicalAssetType = model.Datastore
			default:
				panic(errors.New("unknown 'type' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Type)))
			}

			var technicalAssetSize model.TechnicalAssetSize
			switch asset.Size {
			case model.Service.String():
				technicalAssetSize = model.Service
			case model.System.String():
				technicalAssetSize = model.System
			case model.Application.String():
				technicalAssetSize = model.Application
			case model.Component.String():
				technicalAssetSize = model.Component
			default:
				panic(errors.New("unknown 'size' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Size)))
			}

			var technicalAssetTechnology model.TechnicalAssetTechnology
			switch asset.Technology {
			case model.UnknownTechnology.String():
				technicalAssetTechnology = model.UnknownTechnology
			case model.ClientSystem.String():
				technicalAssetTechnology = model.ClientSystem
			case model.Browser.String():
				technicalAssetTechnology = model.Browser
			case model.Desktop.String():
				technicalAssetTechnology = model.Desktop
			case model.MobileApp.String():
				technicalAssetTechnology = model.MobileApp
			case model.DevOpsClient.String():
				technicalAssetTechnology = model.DevOpsClient
			case model.WebServer.String():
				technicalAssetTechnology = model.WebServer
			case model.WebApplication.String():
				technicalAssetTechnology = model.WebApplication
			case model.ApplicationServer.String():
				technicalAssetTechnology = model.ApplicationServer
			case model.Database.String():
				technicalAssetTechnology = model.Database
			case model.FileServer.String():
				technicalAssetTechnology = model.FileServer
			case model.LocalFileSystem.String():
				technicalAssetTechnology = model.LocalFileSystem
			case model.ERP.String():
				technicalAssetTechnology = model.ERP
			case model.CMS.String():
				technicalAssetTechnology = model.CMS
			case model.WebServiceREST.String():
				technicalAssetTechnology = model.WebServiceREST
			case model.WebServiceSOAP.String():
				technicalAssetTechnology = model.WebServiceSOAP
			case model.EJB.String():
				technicalAssetTechnology = model.EJB
			case model.SearchIndex.String():
				technicalAssetTechnology = model.SearchIndex
			case model.SearchEngine.String():
				technicalAssetTechnology = model.SearchEngine
			case model.ServiceRegistry.String():
				technicalAssetTechnology = model.ServiceRegistry
			case model.ReverseProxy.String():
				technicalAssetTechnology = model.ReverseProxy
			case model.LoadBalancer.String():
				technicalAssetTechnology = model.LoadBalancer
			case model.BuildPipeline.String():
				technicalAssetTechnology = model.BuildPipeline
			case model.SourcecodeRepository.String():
				technicalAssetTechnology = model.SourcecodeRepository
			case model.ArtifactRegistry.String():
				technicalAssetTechnology = model.ArtifactRegistry
			case model.CodeInspectionPlatform.String():
				technicalAssetTechnology = model.CodeInspectionPlatform
			case model.Monitoring.String():
				technicalAssetTechnology = model.Monitoring
			case model.LDAPServer.String():
				technicalAssetTechnology = model.LDAPServer
			case model.ContainerPlatform.String():
				technicalAssetTechnology = model.ContainerPlatform
			case model.BatchProcessing.String():
				technicalAssetTechnology = model.BatchProcessing
			case model.EventListener.String():
				technicalAssetTechnology = model.EventListener
			case model.IdentityProvider.String():
				technicalAssetTechnology = model.IdentityProvider
			case model.IdentityStoreLDAP.String():
				technicalAssetTechnology = model.IdentityStoreLDAP
			case model.IdentityStoreDatabase.String():
				technicalAssetTechnology = model.IdentityStoreDatabase
			case model.Tool.String():
				technicalAssetTechnology = model.Tool
			case model.CLI.String():
				technicalAssetTechnology = model.CLI
			case model.Task.String():
				technicalAssetTechnology = model.Task
			case model.Function.String():
				technicalAssetTechnology = model.Function
			case model.Gateway.String():
				technicalAssetTechnology = model.Gateway
			case model.IoTDevice.String():
				technicalAssetTechnology = model.IoTDevice
			case model.MessageQueue.String():
				technicalAssetTechnology = model.MessageQueue
			case model.StreamProcessing.String():
				technicalAssetTechnology = model.StreamProcessing
			case model.ServiceMesh.String():
				technicalAssetTechnology = model.ServiceMesh
			case model.DataLake.String():
				technicalAssetTechnology = model.DataLake
			case model.BigDataPlatform.String():
				technicalAssetTechnology = model.BigDataPlatform
			case model.ReportEngine.String():
				technicalAssetTechnology = model.ReportEngine
			case model.AI.String():
				technicalAssetTechnology = model.AI
			case model.MailServer.String():
				technicalAssetTechnology = model.MailServer
			case model.Vault.String():
				technicalAssetTechnology = model.Vault
			case model.HSM.String():
				technicalAssetTechnology = model.HSM
			case model.WAF.String():
				technicalAssetTechnology = model.WAF
			case model.IDS.String():
				technicalAssetTechnology = model.IDS
			case model.IPS.String():
				technicalAssetTechnology = model.IPS
			case model.Scheduler.String():
				technicalAssetTechnology = model.Scheduler
			case model.Mainframe.String():
				technicalAssetTechnology = model.Mainframe
			case model.BlockStorage.String():
				technicalAssetTechnology = model.BlockStorage
			case model.Library.String():
				technicalAssetTechnology = model.Library
			default:
				panic(errors.New("unknown 'technology' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Technology)))
			}

			var encryption model.EncryptionStyle
			switch asset.Encryption {
			case model.NoneEncryption.String():
				encryption = model.NoneEncryption
			case model.Transparent.String():
				encryption = model.Transparent
			case model.DataWithSymmetricSharedKey.String():
				encryption = model.DataWithSymmetricSharedKey
			case model.DataWithAsymmetricSharedKey.String():
				encryption = model.DataWithAsymmetricSharedKey
			case model.DataWithEndUserIndividualKey.String():
				encryption = model.DataWithEndUserIndividualKey
			default:
				panic(errors.New("unknown 'encryption' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Encryption)))
			}

			var technicalAssetMachine model.TechnicalAssetMachine
			switch asset.Machine {
			case model.Physical.String():
				technicalAssetMachine = model.Physical
			case model.Virtual.String():
				technicalAssetMachine = model.Virtual
			case model.Container.String():
				technicalAssetMachine = model.Container
			case model.Serverless.String():
				technicalAssetMachine = model.Serverless
			default:
				panic(errors.New("unknown 'machine' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Machine)))
			}

			var confidentiality model.Confidentiality
			switch asset.Confidentiality {
			case model.Public.String():
				confidentiality = model.Public
			case model.Internal.String():
				confidentiality = model.Internal
			case model.Restricted.String():
				confidentiality = model.Restricted
			case model.Confidential.String():
				confidentiality = model.Confidential
			case model.StrictlyConfidential.String():
				confidentiality = model.StrictlyConfidential
			default:
				panic(errors.New("unknown 'confidentiality' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Confidentiality)))
			}

			var integrity model.Criticality
			switch asset.Integrity {
			case model.Archive.String():
				integrity = model.Archive
			case model.Operational.String():
				integrity = model.Operational
			case model.Important.String():
				integrity = model.Important
			case model.Critical.String():
				integrity = model.Critical
			case model.MissionCritical.String():
				integrity = model.MissionCritical
			default:
				panic(errors.New("unknown 'integrity' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Integrity)))
			}

			var availability model.Criticality
			switch asset.Availability {
			case model.Archive.String():
				availability = model.Archive
			case model.Operational.String():
				availability = model.Operational
			case model.Important.String():
				availability = model.Important
			case model.Critical.String():
				availability = model.Critical
			case model.MissionCritical.String():
				availability = model.MissionCritical
			default:
				panic(errors.New("unknown 'availability' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Availability)))
			}

			dataFormatsAccepted := make([]model.DataFormat, 0)
			if asset.DataFormatsAccepted != nil {
				for _, dataFormatName := range asset.DataFormatsAccepted {
					switch dataFormatName {
					case model.JSON.String():
						dataFormatsAccepted = append(dataFormatsAccepted, model.JSON)
					case model.XML.String():
						dataFormatsAccepted = append(dataFormatsAccepted, model.XML)
					case model.Serialization.String():
						dataFormatsAccepted = append(dataFormatsAccepted, model.Serialization)
					case model.File.String():
						dataFormatsAccepted = append(dataFormatsAccepted, model.File)
					case model.CSV.String():
						dataFormatsAccepted = append(dataFormatsAccepted, model.CSV)
					default:
						panic(errors.New("unknown 'data_formats_accepted' value of technical asset '" + title + "': " + fmt.Sprintf("%v", dataFormatName)))
					}
				}
			}

			communicationLinks := make([]model.CommunicationLink, 0)
			if asset.CommunicationLinks != nil {
				for commLinkTitle, commLink := range asset.CommunicationLinks {
					constraint := true
					weight := 1
					var protocol model.Protocol
					var authentication model.Authentication
					var authorization model.Authorization
					var usage model.Usage
					var dataAssetsSent []string
					var dataAssetsReceived []string

					switch commLink.Authentication {
					case model.NoneAuthentication.String():
						authentication = model.NoneAuthentication
					case model.Credentials.String():
						authentication = model.Credentials
					case model.SessionId.String():
						authentication = model.SessionId
					case model.Token.String():
						authentication = model.Token
					case model.ClientCertificate.String():
						authentication = model.ClientCertificate
					case model.TwoFactor.String():
						authentication = model.TwoFactor
					case model.Externalized.String():
						authentication = model.Externalized
					default:
						panic(errors.New("unknown 'authentication' value of technical asset '" + title + "' communication link '" + commLinkTitle + "': " + fmt.Sprintf("%v", commLink.Authentication)))
					}

					switch commLink.Authorization {
					case model.NoneAuthorization.String():
						authorization = model.NoneAuthorization
					case model.TechnicalUser.String():
						authorization = model.TechnicalUser
					case model.EndUserIdentityPropagation.String():
						authorization = model.EndUserIdentityPropagation
					default:
						panic(errors.New("unknown 'authorization' value of technical asset '" + title + "' communication link '" + commLinkTitle + "': " + fmt.Sprintf("%v", commLink.Authorization)))
					}

					switch commLink.Usage {
					case model.Business.String():
						usage = model.Business
					case model.DevOps.String():
						usage = model.DevOps
					default:
						panic(errors.New("unknown 'usage' value of technical asset '" + title + "' communication link '" + commLinkTitle + "': " + fmt.Sprintf("%v", commLink.Usage)))
					}

					switch commLink.Protocol {
					case model.UnknownProtocol.String():
						protocol = model.UnknownProtocol
					case model.HTTP.String():
						protocol = model.HTTP
					case model.HTTPS.String():
						protocol = model.HTTPS
					case model.WS.String():
						protocol = model.WS
					case model.WSS.String():
						protocol = model.WSS
					case model.MQTT.String():
						protocol = model.MQTT
					case model.JDBC.String():
						protocol = model.JDBC
					case model.JdbcEncrypted.String():
						protocol = model.JdbcEncrypted
					case model.ODBC.String():
						protocol = model.ODBC
					case model.OdbcEncrypted.String():
						protocol = model.OdbcEncrypted
					case model.SqlAccessProtocol.String():
						protocol = model.SqlAccessProtocol
					case model.SqlAccessProtocolEncrypted.String():
						protocol = model.SqlAccessProtocolEncrypted
					case model.NosqlAccessProtocol.String():
						protocol = model.NosqlAccessProtocol
					case model.NosqlAccessProtocolEncrypted.String():
						protocol = model.NosqlAccessProtocolEncrypted
					case model.TEXT.String():
						protocol = model.TEXT
					case model.TextEncrypted.String():
						protocol = model.TextEncrypted
					case model.BINARY.String():
						protocol = model.BINARY
					case model.BinaryEncrypted.String():
						protocol = model.BinaryEncrypted
					case model.SSH.String():
						protocol = model.SSH
					case model.SshTunnel.String():
						protocol = model.SshTunnel
					case model.SMTP.String():
						protocol = model.SMTP
					case model.SmtpEncrypted.String():
						protocol = model.SmtpEncrypted
					case model.POP3.String():
						protocol = model.POP3
					case model.Pop3Encrypted.String():
						protocol = model.Pop3Encrypted
					case model.IMAP.String():
						protocol = model.IMAP
					case model.ImapEncrypted.String():
						protocol = model.ImapEncrypted
					case model.FTP.String():
						protocol = model.FTP
					case model.FTPS.String():
						protocol = model.FTPS
					case model.SFTP.String():
						protocol = model.SFTP
					case model.SCP.String():
						protocol = model.SCP
					case model.LDAP.String():
						protocol = model.LDAP
					case model.LDAPS.String():
						protocol = model.LDAPS
					case model.JMS.String():
						protocol = model.JMS
					case model.NFS.String():
						protocol = model.NFS
					case model.SMB.String():
						protocol = model.SMB
					case model.SmbEncrypted.String():
						protocol = model.SmbEncrypted
					case model.LocalFileAccess.String():
						protocol = model.LocalFileAccess
					case model.NRPE.String():
						protocol = model.NRPE
					case model.XMPP.String():
						protocol = model.XMPP
					case model.IIOP.String():
						protocol = model.IIOP
					case model.IiopEncrypted.String():
						protocol = model.IiopEncrypted
					case model.JRMP.String():
						protocol = model.JRMP
					case model.JrmpEncrypted.String():
						protocol = model.JrmpEncrypted
					case model.InProcessLibraryCall.String():
						protocol = model.InProcessLibraryCall
					case model.ContainerSpawning.String():
						protocol = model.ContainerSpawning
					default:
						panic(errors.New("unknown 'protocol' of technical asset '" + title + "' communication link '" + commLinkTitle + "': " + fmt.Sprintf("%v", commLink.Protocol)))
					}

					if commLink.DataAssetsSent != nil {
						for _, dataAssetSent := range commLink.DataAssetsSent {
							referencedAsset := fmt.Sprintf("%v", dataAssetSent)
							checkDataAssetTargetExists(referencedAsset, "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
							dataAssetsSent = append(dataAssetsSent, referencedAsset)
						}
					}

					if commLink.DataAssetsReceived != nil {
						for _, dataAssetReceived := range commLink.DataAssetsReceived {
							referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
							checkDataAssetTargetExists(referencedAsset, "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
							dataAssetsReceived = append(dataAssetsReceived, referencedAsset)
						}
					}

					if commLink.DiagramTweakWeight > 0 {
						weight = commLink.DiagramTweakWeight
					}

					constraint = !commLink.DiagramTweakConstraint

					checkErr(err)

					dataFlowTitle := fmt.Sprintf("%v", commLinkTitle)
					commLink := model.CommunicationLink{
						Id:                     createDataFlowId(id, dataFlowTitle),
						SourceId:               id,
						TargetId:               commLink.Target,
						Title:                  dataFlowTitle,
						Description:            withDefault(commLink.Description, dataFlowTitle),
						Protocol:               protocol,
						Authentication:         authentication,
						Authorization:          authorization,
						Usage:                  usage,
						Tags:                   checkTags(lowerCaseAndTrim(commLink.Tags), "communication link '"+commLinkTitle+"' of technical asset '"+title+"'"),
						VPN:                    commLink.VPN,
						IpFiltered:             commLink.IpFiltered,
						Readonly:               commLink.Readonly,
						DataAssetsSent:         dataAssetsSent,
						DataAssetsReceived:     dataAssetsReceived,
						DiagramTweakWeight:     weight,
						DiagramTweakConstraint: constraint,
					}
					communicationLinks = append(communicationLinks, commLink)
					// track all comm links
					model.CommunicationLinks[commLink.Id] = commLink
					// keep track of map of *all* comm links mapped by target-id (to be able to look up "who is calling me" kind of things)
					model.IncomingTechnicalCommunicationLinksMappedByTargetId[commLink.TargetId] = append(
						model.IncomingTechnicalCommunicationLinksMappedByTargetId[commLink.TargetId], commLink)
				}
			}

			checkIdSyntax(id)
			if _, exists := model.ParsedModelRoot.TechnicalAssets[id]; exists {
				panic(errors.New("duplicate id used: " + id))
			}
			model.ParsedModelRoot.TechnicalAssets[id] = model.TechnicalAsset{
				Id:                      id,
				Usage:                   usage,
				Title:                   title, //fmt.Sprintf("%v", asset["title"]),
				Description:             withDefault(fmt.Sprintf("%v", asset.Description), title),
				Type:                    technicalAssetType,
				Size:                    technicalAssetSize,
				Technology:              technicalAssetTechnology,
				Tags:                    checkTags(lowerCaseAndTrim(asset.Tags), "technical asset '"+title+"'"),
				Machine:                 technicalAssetMachine,
				Internet:                asset.Internet,
				Encryption:              encryption,
				MultiTenant:             asset.MultiTenant,
				Redundant:               asset.Redundant,
				CustomDevelopedParts:    asset.CustomDevelopedParts,
				UsedAsClientByHuman:     asset.UsedAsClientByHuman,
				OutOfScope:              asset.OutOfScope,
				JustificationOutOfScope: fmt.Sprintf("%v", asset.JustificationOutOfScope),
				Owner:                   fmt.Sprintf("%v", asset.Owner),
				Confidentiality:         confidentiality,
				Integrity:               integrity,
				Availability:            availability,
				JustificationCiaRating:  fmt.Sprintf("%v", asset.JustificationCiaRating),
				DataAssetsProcessed:     dataAssetsProcessed,
				DataAssetsStored:        dataAssetsStored,
				DataFormatsAccepted:     dataFormatsAccepted,
				CommunicationLinks:      communicationLinks,
				DiagramTweakOrder:       asset.DiagramTweakOrder,
			}
		}

		// Trust Boundaries ===============================================================================
		checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries := make(map[string]bool)
		model.ParsedModelRoot.TrustBoundaries = make(map[string]model.TrustBoundary)
		for title, boundary := range modelInput.TrustBoundaries {
			id := fmt.Sprintf("%v", boundary.ID)

			var technicalAssetsInside = make([]string, 0)
			if boundary.TechnicalAssetsInside != nil {
				parsedInsideAssets := boundary.TechnicalAssetsInside
				technicalAssetsInside = make([]string, len(parsedInsideAssets))
				for i, parsedInsideAsset := range parsedInsideAssets {
					technicalAssetsInside[i] = fmt.Sprintf("%v", parsedInsideAsset)
					_, found := model.ParsedModelRoot.TechnicalAssets[technicalAssetsInside[i]]
					if !found {
						panic(errors.New("missing referenced technical asset " + technicalAssetsInside[i] + " at trust boundary '" + title + "'"))
					}
					if checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries[technicalAssetsInside[i]] == true {
						panic(errors.New("referenced technical asset " + technicalAssetsInside[i] + " at trust boundary '" + title + "' is modeled in multiple trust boundaries"))
					}
					checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries[technicalAssetsInside[i]] = true
					//fmt.Println("asset "+technicalAssetsInside[i]+" at i="+strconv.Itoa(i))
				}
			}

			var trustBoundariesNested = make([]string, 0)
			if boundary.TrustBoundariesNested != nil {
				parsedNestedBoundaries := boundary.TrustBoundariesNested
				trustBoundariesNested = make([]string, len(parsedNestedBoundaries))
				for i, parsedNestedBoundary := range parsedNestedBoundaries {
					trustBoundariesNested[i] = fmt.Sprintf("%v", parsedNestedBoundary)
				}
			}

			var trustBoundaryType model.TrustBoundaryType
			switch boundary.Type {
			case model.NetworkOnPrem.String():
				trustBoundaryType = model.NetworkOnPrem
			case model.NetworkDedicatedHoster.String():
				trustBoundaryType = model.NetworkDedicatedHoster
			case model.NetworkVirtualLAN.String():
				trustBoundaryType = model.NetworkVirtualLAN
			case model.NetworkCloudProvider.String():
				trustBoundaryType = model.NetworkCloudProvider
			case model.NetworkCloudSecurityGroup.String():
				trustBoundaryType = model.NetworkCloudSecurityGroup
			case model.NetworkPolicyNamespaceIsolation.String():
				trustBoundaryType = model.NetworkPolicyNamespaceIsolation
			case model.ExecutionEnvironment.String():
				trustBoundaryType = model.ExecutionEnvironment
			default:
				panic(errors.New("unknown 'type' of trust boundary '" + title + "': " + fmt.Sprintf("%v", boundary.Type)))
			}

			trustBoundary := model.TrustBoundary{
				Id:                    id,
				Title:                 title, //fmt.Sprintf("%v", boundary["title"]),
				Description:           withDefault(fmt.Sprintf("%v", boundary.Description), title),
				Type:                  trustBoundaryType,
				Tags:                  checkTags(lowerCaseAndTrim(boundary.Tags), "trust boundary '"+title+"'"),
				TechnicalAssetsInside: technicalAssetsInside,
				TrustBoundariesNested: trustBoundariesNested,
			}
			checkIdSyntax(id)
			if _, exists := model.ParsedModelRoot.TrustBoundaries[id]; exists {
				panic(errors.New("duplicate id used: " + id))
			}
			model.ParsedModelRoot.TrustBoundaries[id] = trustBoundary
			for _, technicalAsset := range trustBoundary.TechnicalAssetsInside {
				model.DirectContainingTrustBoundaryMappedByTechnicalAssetId[technicalAsset] = trustBoundary
				//fmt.Println("Asset "+technicalAsset+" is directly in trust boundary "+trustBoundary.Id)
			}
		}
		checkNestedTrustBoundariesExisting()

		// Shared Runtime ===============================================================================
		model.ParsedModelRoot.SharedRuntimes = make(map[string]model.SharedRuntime)
		for title, runtime := range modelInput.SharedRuntimes {
			id := fmt.Sprintf("%v", runtime.ID)

			var technicalAssetsRunning = make([]string, 0)
			if runtime.TechnicalAssetsRunning != nil {
				parsedRunningAssets := runtime.TechnicalAssetsRunning
				technicalAssetsRunning = make([]string, len(parsedRunningAssets))
				for i, parsedRunningAsset := range parsedRunningAssets {
					assetId := fmt.Sprintf("%v", parsedRunningAsset)
					checkTechnicalAssetExists(assetId, "shared runtime '"+title+"'", false)
					technicalAssetsRunning[i] = assetId
				}
			}

			sharedRuntime := model.SharedRuntime{
				Id:                     id,
				Title:                  title, //fmt.Sprintf("%v", boundary["title"]),
				Description:            withDefault(fmt.Sprintf("%v", runtime.Description), title),
				Tags:                   checkTags(runtime.Tags, "shared runtime '"+title+"'"),
				TechnicalAssetsRunning: technicalAssetsRunning,
			}
			checkIdSyntax(id)
			if _, exists := model.ParsedModelRoot.SharedRuntimes[id]; exists {
				panic(errors.New("duplicate id used: " + id))
			}
			model.ParsedModelRoot.SharedRuntimes[id] = sharedRuntime
			for _, technicalAssetId := range sharedRuntime.TechnicalAssetsRunning {
				model.DirectContainingSharedRuntimeMappedByTechnicalAssetId[technicalAssetId] = sharedRuntime
			}
		}

		// Individual Risk Categories (just used as regular risk categories) ===============================================================================
		model.ParsedModelRoot.IndividualRiskCategories = make(map[string]model.RiskCategory)
		for title, individualCategory := range modelInput.IndividualRiskCategories {
			id := fmt.Sprintf("%v", individualCategory.ID)

			var function model.RiskFunction
			switch individualCategory.Function {
			case model.BusinessSide.String():
				function = model.BusinessSide
			case model.Architecture.String():
				function = model.Architecture
			case model.Development.String():
				function = model.Development
			case model.Operations.String():
				function = model.Operations
			default:
				panic(errors.New("unknown 'function' value of individual risk category '" + title + "': " + fmt.Sprintf("%v", individualCategory.Function)))
			}

			var stride model.STRIDE
			switch individualCategory.STRIDE {
			case model.Spoofing.String():
				stride = model.Spoofing
			case model.Tampering.String():
				stride = model.Tampering
			case model.Repudiation.String():
				stride = model.Repudiation
			case model.InformationDisclosure.String():
				stride = model.InformationDisclosure
			case model.DenialOfService.String():
				stride = model.DenialOfService
			case model.ElevationOfPrivilege.String():
				stride = model.ElevationOfPrivilege
			default:
				panic(errors.New("unknown 'stride' value of individual risk category '" + title + "': " + fmt.Sprintf("%v", individualCategory.STRIDE)))
			}

			cat := model.RiskCategory{
				Id:                         id,
				Title:                      title,
				Description:                withDefault(fmt.Sprintf("%v", individualCategory.Description), title),
				Impact:                     fmt.Sprintf("%v", individualCategory.Impact),
				ASVS:                       fmt.Sprintf("%v", individualCategory.ASVS),
				CheatSheet:                 fmt.Sprintf("%v", individualCategory.CheatSheet),
				Action:                     fmt.Sprintf("%v", individualCategory.Action),
				Mitigation:                 fmt.Sprintf("%v", individualCategory.Mitigation),
				Check:                      fmt.Sprintf("%v", individualCategory.Check),
				DetectionLogic:             fmt.Sprintf("%v", individualCategory.DetectionLogic),
				RiskAssessment:             fmt.Sprintf("%v", individualCategory.RiskAssessment),
				FalsePositives:             fmt.Sprintf("%v", individualCategory.FalsePositives),
				Function:                   function,
				STRIDE:                     stride,
				ModelFailurePossibleReason: individualCategory.ModelFailurePossibleReason,
				CWE:                        individualCategory.CWE,
			}
			checkIdSyntax(id)
			if _, exists := model.ParsedModelRoot.IndividualRiskCategories[id]; exists {
				panic(errors.New("duplicate id used: " + id))
			}
			model.ParsedModelRoot.IndividualRiskCategories[id] = cat

			// NOW THE INDIVIDUAL RISK INSTANCES:
			//individualRiskInstances := make([]model.Risk, 0)
			if individualCategory.RisksIdentified != nil { // TODO: also add syntax checks of input YAML when linked asset is not found or when synthetic-id is already used...
				for title, individualRiskInstance := range individualCategory.RisksIdentified {
					var severity model.RiskSeverity
					var exploitationLikelihood model.RiskExploitationLikelihood
					var exploitationImpact model.RiskExploitationImpact
					var mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string
					var dataBreachProbability model.DataBreachProbability
					var dataBreachTechnicalAssetIDs []string

					switch individualRiskInstance.Severity {
					case model.LowSeverity.String():
						severity = model.LowSeverity
					case model.MediumSeverity.String():
						severity = model.MediumSeverity
					case model.ElevatedSeverity.String():
						severity = model.ElevatedSeverity
					case model.HighSeverity.String():
						severity = model.HighSeverity
					case model.CriticalSeverity.String():
						severity = model.CriticalSeverity
					case "": // added default
						severity = model.MediumSeverity
					default:
						panic(errors.New("unknown 'severity' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", individualRiskInstance.Severity)))
					}

					switch individualRiskInstance.ExploitationLikelihood {
					case model.Unlikely.String():
						exploitationLikelihood = model.Unlikely
					case model.Likely.String():
						exploitationLikelihood = model.Likely
					case model.VeryLikely.String():
						exploitationLikelihood = model.VeryLikely
					case model.Frequent.String():
						exploitationLikelihood = model.Frequent
					case "": // added default
						exploitationLikelihood = model.Likely
					default:
						panic(errors.New("unknown 'exploitation_likelihood' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", individualRiskInstance.ExploitationLikelihood)))
					}

					switch individualRiskInstance.ExploitationImpact {
					case model.LowImpact.String():
						exploitationImpact = model.LowImpact
					case model.MediumImpact.String():
						exploitationImpact = model.MediumImpact
					case model.HighImpact.String():
						exploitationImpact = model.HighImpact
					case model.VeryHighImpact.String():
						exploitationImpact = model.VeryHighImpact
					case "": // added default
						exploitationImpact = model.MediumImpact
					default:
						panic(errors.New("unknown 'exploitation_impact' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", individualRiskInstance.ExploitationImpact)))
					}

					if len(individualRiskInstance.MostRelevantDataAsset) > 0 {
						mostRelevantDataAssetId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantDataAsset)
						checkDataAssetTargetExists(mostRelevantDataAssetId, "individual risk '"+title+"'")
					}

					if len(individualRiskInstance.MostRelevantTechnicalAsset) > 0 {
						mostRelevantTechnicalAssetId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantTechnicalAsset)
						checkTechnicalAssetExists(mostRelevantTechnicalAssetId, "individual risk '"+title+"'", false)
					}

					if len(individualRiskInstance.MostRelevantCommunicationLink) > 0 {
						mostRelevantCommunicationLinkId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantCommunicationLink)
						checkCommunicationLinkExists(mostRelevantCommunicationLinkId, "individual risk '"+title+"'")
					}

					if len(individualRiskInstance.MostRelevantTrustBoundary) > 0 {
						mostRelevantTrustBoundaryId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantTrustBoundary)
						checkTrustBoundaryExists(mostRelevantTrustBoundaryId, "individual risk '"+title+"'")
					}

					if len(individualRiskInstance.MostRelevantSharedRuntime) > 0 {
						mostRelevantSharedRuntimeId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantSharedRuntime)
						checkSharedRuntimeExists(mostRelevantSharedRuntimeId, "individual risk '"+title+"'")
					}

					switch individualRiskInstance.DataBreachProbability {
					case model.Improbable.String():
						dataBreachProbability = model.Improbable
					case model.Possible.String():
						dataBreachProbability = model.Possible
					case model.Probable.String():
						dataBreachProbability = model.Probable
					case "": // added default
						dataBreachProbability = model.Possible
					default:
						panic(errors.New("unknown 'data_breach_probability' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", individualRiskInstance.DataBreachProbability)))
					}

					if individualRiskInstance.DataBreachTechnicalAssets != nil {
						dataBreachTechnicalAssetIDs = make([]string, len(individualRiskInstance.DataBreachTechnicalAssets))
						for i, parsedReferencedAsset := range individualRiskInstance.DataBreachTechnicalAssets {
							assetId := fmt.Sprintf("%v", parsedReferencedAsset)
							checkTechnicalAssetExists(assetId, "data breach technical assets of individual risk '"+title+"'", false)
							dataBreachTechnicalAssetIDs[i] = assetId
						}
					}

					checkErr(err)

					individualRiskInstance := model.Risk{
						SyntheticId:                     createSyntheticId(cat.Id, mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId),
						Title:                           fmt.Sprintf("%v", title),
						Category:                        cat,
						Severity:                        severity,
						ExploitationLikelihood:          exploitationLikelihood,
						ExploitationImpact:              exploitationImpact,
						MostRelevantDataAssetId:         mostRelevantDataAssetId,
						MostRelevantTechnicalAssetId:    mostRelevantTechnicalAssetId,
						MostRelevantCommunicationLinkId: mostRelevantCommunicationLinkId,
						MostRelevantTrustBoundaryId:     mostRelevantTrustBoundaryId,
						MostRelevantSharedRuntimeId:     mostRelevantSharedRuntimeId,
						DataBreachProbability:           dataBreachProbability,
						DataBreachTechnicalAssetIDs:     dataBreachTechnicalAssetIDs,
					}
					model.GeneratedRisksByCategory[cat] = append(model.GeneratedRisksByCategory[cat], individualRiskInstance)
				}
			}
		}

		// Risk Tracking ===============================================================================
		model.ParsedModelRoot.RiskTracking = make(map[string]model.RiskTracking)
		for syntheticRiskId, riskTracking := range modelInput.RiskTracking {
			justification := fmt.Sprintf("%v", riskTracking.Justification)
			checkedBy := fmt.Sprintf("%v", riskTracking.CheckedBy)
			ticket := fmt.Sprintf("%v", riskTracking.Ticket)
			var date time.Time
			if len(riskTracking.Date) > 0 {
				date, err = time.Parse("2006-01-02", riskTracking.Date)
				if err != nil {
					panic(errors.New("unable to parse 'date' of risk tracking '" + syntheticRiskId + "': " + riskTracking.Date))
				}
			}

			var status model.RiskStatus
			switch riskTracking.Status {
			case model.Unchecked.String():
				status = model.Unchecked
			case model.Mitigated.String():
				status = model.Mitigated
			case model.InProgress.String():
				status = model.InProgress
			case model.Accepted.String():
				status = model.Accepted
			case model.InDiscussion.String():
				status = model.InDiscussion
			case model.FalsePositive.String():
				status = model.FalsePositive
			default:
				panic(errors.New("unknown 'status' value of risk tracking '" + syntheticRiskId + "': " + riskTracking.Status))
			}

			tracking := model.RiskTracking{
				SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
				Justification:   justification,
				CheckedBy:       checkedBy,
				Ticket:          ticket,
				Date:            date,
				Status:          status,
			}
			if strings.Contains(syntheticRiskId, "*") { // contains a wildcard char
				deferredRiskTrackingDueToWildcardMatching[syntheticRiskId] = tracking
			} else {
				model.ParsedModelRoot.RiskTracking[syntheticRiskId] = tracking
			}
		}

		// ====================== model consistency check (linking)
		for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
			for _, commLink := range technicalAsset.CommunicationLinks {
				checkTechnicalAssetExists(commLink.TargetId, "communication link '"+commLink.Title+"' of technical asset '"+technicalAsset.Title+"'", false)
			}
		}
	} else {
		log.Fatal("Unable to read/parse model yaml: ", err)
	}
}

func lowerCaseAndTrim(tags []string) []string {
	for i := range tags {
		tags[i] = strings.ToLower(strings.TrimSpace(tags[i]))
	}
	return tags
}

func checkTags(tags []string, where string) []string {
	var tagsUsed = make([]string, 0)
	if tags != nil {
		tagsUsed = make([]string, len(tags))
		for i, parsedEntry := range tags {
			referencedTag := fmt.Sprintf("%v", parsedEntry)
			checkTagExists(referencedTag, where)
			tagsUsed[i] = referencedTag
		}
	}
	return tagsUsed
}

// in order to prevent Path-Traversal like stuff...
func removePathElementsFromImageFiles(overview model.Overview) model.Overview {
	for i := range overview.Images {
		newValue := make(map[string]string)
		for file, desc := range overview.Images[i] {
			newValue[filepath.Base(file)] = desc
		}
		overview.Images[i] = newValue
	}
	return overview
}

func applyWildcardRiskTrackingEvaluation() {
	if *verbose {
		fmt.Println("Executing risk tracking evaluation")
	}
	for syntheticRiskIdPattern, riskTracking := range deferredRiskTrackingDueToWildcardMatching {
		foundSome := false
		var matchingRiskIdExpression = regexp.MustCompile(strings.ReplaceAll(regexp.QuoteMeta(syntheticRiskIdPattern), `\*`, `[^@]+`))
		for syntheticRiskId := range model.GeneratedRisksBySyntheticId {
			if matchingRiskIdExpression.Match([]byte(syntheticRiskId)) && hasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId) {
				foundSome = true
				model.ParsedModelRoot.RiskTracking[syntheticRiskId] = model.RiskTracking{
					SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
					Justification:   riskTracking.Justification,
					CheckedBy:       riskTracking.CheckedBy,
					Ticket:          riskTracking.Ticket,
					Status:          riskTracking.Status,
					Date:            riskTracking.Date,
				}
			}
		}
		if !foundSome {
			if *ignoreOrphanedRiskTracking {
				fmt.Println("Wildcard risk tracking does not match any risk id: " + syntheticRiskIdPattern)
			} else {
				panic(errors.New("wildcard risk tracking does not match any risk id: " + syntheticRiskIdPattern))
			}
		}
	}
}

func hasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId string) bool {
	if _, ok := model.ParsedModelRoot.RiskTracking[syntheticRiskId]; ok {
		return false
	}
	return true
}

func withDefault(value string, defaultWhenEmpty string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > 0 && trimmed != "<nil>" {
		return trimmed
	}
	return strings.TrimSpace(defaultWhenEmpty)
}

func createDataFlowId(sourceAssetId, title string) string {
	reg, err := regexp.Compile("[^A-Za-z0-9]+")
	checkErr(err)
	return sourceAssetId + ">" + strings.Trim(reg.ReplaceAllString(strings.ToLower(title), "-"), "- ")
}

func createSyntheticId(categoryId string,
	mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string) string {
	result := categoryId
	if len(mostRelevantTechnicalAssetId) > 0 {
		result += "@" + mostRelevantTechnicalAssetId
	}
	if len(mostRelevantCommunicationLinkId) > 0 {
		result += "@" + mostRelevantCommunicationLinkId
	}
	if len(mostRelevantTrustBoundaryId) > 0 {
		result += "@" + mostRelevantTrustBoundaryId
	}
	if len(mostRelevantSharedRuntimeId) > 0 {
		result += "@" + mostRelevantSharedRuntimeId
	}
	if len(mostRelevantDataAssetId) > 0 {
		result += "@" + mostRelevantDataAssetId
	}
	return result
}

func checkTagExists(referencedTag, where string) {
	if !model.Contains(model.ParsedModelRoot.TagsAvailable, referencedTag) {
		panic(errors.New("missing referenced tag in overall tag list at " + where + ": " + referencedTag))
	}
}

func checkDataAssetTargetExists(referencedAsset, where string) {
	if _, ok := model.ParsedModelRoot.DataAssets[referencedAsset]; !ok {
		panic(errors.New("missing referenced data asset target at " + where + ": " + referencedAsset))
	}
}

func checkTrustBoundaryExists(referencedId, where string) {
	if _, ok := model.ParsedModelRoot.TrustBoundaries[referencedId]; !ok {
		panic(errors.New("missing referenced trust boundary at " + where + ": " + referencedId))
	}
}

func checkSharedRuntimeExists(referencedId, where string) {
	if _, ok := model.ParsedModelRoot.SharedRuntimes[referencedId]; !ok {
		panic(errors.New("missing referenced shared runtime at " + where + ": " + referencedId))
	}
}

func checkCommunicationLinkExists(referencedId, where string) {
	if _, ok := model.CommunicationLinks[referencedId]; !ok {
		panic(errors.New("missing referenced communication link at " + where + ": " + referencedId))
	}
}

func checkTechnicalAssetExists(referencedAsset, where string, onlyForTweak bool) {
	if _, ok := model.ParsedModelRoot.TechnicalAssets[referencedAsset]; !ok {
		suffix := ""
		if onlyForTweak {
			suffix = " (only referenced in diagram tweak)"
		}
		panic(errors.New("missing referenced technical asset target" + suffix + " at " + where + ": " + referencedAsset))
	}
}

func checkNestedTrustBoundariesExisting() {
	for _, trustBoundary := range model.ParsedModelRoot.TrustBoundaries {
		for _, nestedId := range trustBoundary.TrustBoundariesNested {
			if _, ok := model.ParsedModelRoot.TrustBoundaries[nestedId]; !ok {
				panic(errors.New("missing referenced nested trust boundary: " + nestedId))
			}
		}
	}
}

func hash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%v", h.Sum32())
}

func writeDataAssetDiagramGraphvizDOT(diagramFilenameDOT string, dpi int) *os.File {
	if *verbose {
		fmt.Println("Writing data asset diagram input")
	}
	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=true \n")

	// Metadata init ===============================================================================
	dotContent.WriteString(`	graph [
		dpi=` + strconv.Itoa(dpi) + `
		fontname="Verdana"
		labelloc="c"
		fontsize="20"
		splines=false
		rankdir="LR"
		nodesep=1.0
		ranksep=3.0
        outputorder="nodesfirst"
	];
	node [
		fontcolor="white"
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`)

	// Technical Assets ===============================================================================
	techAssets := make([]model.TechnicalAsset, 0)
	for _, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(model.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		if len(technicalAsset.DataAssetsStored) > 0 || len(technicalAsset.DataAssetsProcessed) > 0 {
			dotContent.WriteString(makeTechAssetNode(technicalAsset, true))
			dotContent.WriteString("\n")
		}
	}

	// Data Assets ===============================================================================
	dataAssets := make([]model.DataAsset, 0)
	for _, dataAsset := range model.ParsedModelRoot.DataAssets {
		dataAssets = append(dataAssets, dataAsset)
	}
	sort.Sort(model.ByDataAssetDataBreachProbabilityAndTitleSort(dataAssets))
	for _, dataAsset := range dataAssets {
		dotContent.WriteString(makeDataAssetNode(dataAsset))
		dotContent.WriteString("\n")
	}

	// Data Asset to Tech Asset links ===============================================================================
	for _, technicalAsset := range techAssets {
		for _, sourceId := range technicalAsset.DataAssetsStored {
			targetId := technicalAsset.Id
			dotContent.WriteString("\n")
			dotContent.WriteString(hash(sourceId) + " -> " + hash(targetId) +
				` [ color="blue" style="solid" ];`)
			dotContent.WriteString("\n")
		}
		for _, sourceId := range technicalAsset.DataAssetsProcessed {
			if !model.Contains(technicalAsset.DataAssetsStored, sourceId) { // here only if not already drawn above
				targetId := technicalAsset.Id
				dotContent.WriteString("\n")
				dotContent.WriteString(hash(sourceId) + " -> " + hash(targetId) +
					` [ color="#666666" style="dashed" ];`)
				dotContent.WriteString("\n")
			}
		}
	}

	dotContent.WriteString("}")

	// Write the DOT file
	file, err := os.Create(diagramFilenameDOT)
	checkErr(err)
	defer func() { _ = file.Close() }()
	_, err = fmt.Fprintln(file, dotContent.String())
	checkErr(err)
	return file
}

func writeDataFlowDiagramGraphvizDOT(diagramFilenameDOT string, dpi int) *os.File {
	if *verbose {
		fmt.Println("Writing data flow diagram input")
	}
	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=false \n")

	// Metadata init ===============================================================================
	tweaks := ""
	if model.ParsedModelRoot.DiagramTweakNodesep > 0 {
		tweaks += "\n		nodesep=\"" + strconv.Itoa(model.ParsedModelRoot.DiagramTweakNodesep) + "\""
	}
	if model.ParsedModelRoot.DiagramTweakRanksep > 0 {
		tweaks += "\n		ranksep=\"" + strconv.Itoa(model.ParsedModelRoot.DiagramTweakRanksep) + "\""
	}
	suppressBidirectionalArrows := true
	splines := "ortho"
	if len(model.ParsedModelRoot.DiagramTweakEdgeLayout) > 0 {
		switch model.ParsedModelRoot.DiagramTweakEdgeLayout {
		case "spline":
			splines = "spline"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "polyline":
			splines = "polyline"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "ortho":
			splines = "ortho"
			suppressBidirectionalArrows = true
		case "curved":
			splines = "curved"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "false":
			splines = "false"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		default:
			panic(errors.New("unknown value for diagram_tweak_suppress_edge_labels (spline, polyline, ortho, curved, false): " +
				model.ParsedModelRoot.DiagramTweakEdgeLayout))
		}
	}
	rankdir := "TB"
	if model.ParsedModelRoot.DiagramTweakLayoutLeftToRight {
		rankdir = "LR"
	}
	modelTitle := ""
	addModelTitle := false
	if addModelTitle {
		modelTitle = `label="` + model.ParsedModelRoot.Title + `"`
	}
	dotContent.WriteString(`	graph [ ` + modelTitle + `
		labelloc=t
		fontname="Verdana"
		fontsize=40
        outputorder="nodesfirst"
		dpi=` + strconv.Itoa(dpi) + `
		splines=` + splines + `
		rankdir="` + rankdir + `"
` + tweaks + `
	];
	node [
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`)

	// Trust Boundaries ===============================================================================
	var subgraphSnippetsById = make(map[string]string)
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	keys := make([]string, 0)
	for k := range model.ParsedModelRoot.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		trustBoundary := model.ParsedModelRoot.TrustBoundaries[key]
		var snippet strings.Builder
		if len(trustBoundary.TechnicalAssetsInside) > 0 || len(trustBoundary.TrustBoundariesNested) > 0 {
			if drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
				// see https://stackoverflow.com/questions/17247455/how-do-i-add-extra-space-between-clusters?noredirect=1&lq=1
				snippet.WriteString("\n subgraph cluster_space_boundary_for_layout_only_1" + hash(trustBoundary.Id) + " {\n")
				snippet.WriteString(`	graph [
                                              dpi=` + strconv.Itoa(dpi) + `
											  label=<<table border="0" cellborder="0" cellpadding="0" bgcolor="#FFFFFF55"><tr><td><b> </b></td></tr></table>>
											  fontsize="21"
											  style="invis"
											  color="green"
											  fontcolor="green"
											  margin="50.0"
											  penwidth="6.5"
                                              outputorder="nodesfirst"
											];`)
			}
			snippet.WriteString("\n subgraph cluster_" + hash(trustBoundary.Id) + " {\n")
			color, fontColor, bgColor, style, fontname := colors.RgbHexColorTwilight(), colors.RgbHexColorTwilight() /*"#550E0C"*/, "#FAFAFA", "dashed", "Verdana"
			penWidth := 4.5
			if len(trustBoundary.TrustBoundariesNested) > 0 {
				//color, fontColor, style, fontname = colors.Blue, colors.Blue, "dashed", "Verdana"
				penWidth = 5.5
			}
			if len(trustBoundary.ParentTrustBoundaryID()) > 0 {
				bgColor = "#F1F1F1"
			}
			if trustBoundary.Type == model.NetworkPolicyNamespaceIsolation {
				fontColor, bgColor = "#222222", "#DFF4FF"
			}
			if trustBoundary.Type == model.ExecutionEnvironment {
				fontColor, bgColor, style = "#555555", "#FFFFF0", "dotted"
			}
			snippet.WriteString(`	graph [
      dpi=` + strconv.Itoa(dpi) + `
      label=<<table border="0" cellborder="0" cellpadding="0"><tr><td><b>` + trustBoundary.Title + `</b> (` + trustBoundary.Type.String() + `)</td></tr></table>>
      fontsize="21"
      style="` + style + `"
      color="` + color + `"
      bgcolor="` + bgColor + `"
      fontcolor="` + fontColor + `"
      fontname="` + fontname + `"
      penwidth="` + fmt.Sprintf("%f", penWidth) + `"
      forcelabels=true
      outputorder="nodesfirst"
	  margin="50.0"
    ];`)
			snippet.WriteString("\n")
			keys := trustBoundary.TechnicalAssetsInside
			sort.Strings(keys)
			for _, technicalAssetInside := range keys {
				//log.Println("About to add technical asset link to trust boundary: ", technicalAssetInside)
				technicalAsset := model.ParsedModelRoot.TechnicalAssets[technicalAssetInside]
				snippet.WriteString(hash(technicalAsset.Id))
				snippet.WriteString(";\n")
			}
			keys = trustBoundary.TrustBoundariesNested
			sort.Strings(keys)
			for _, trustBoundaryNested := range keys {
				//log.Println("About to add nested trust boundary to trust boundary: ", trustBoundaryNested)
				trustBoundaryNested := model.ParsedModelRoot.TrustBoundaries[trustBoundaryNested]
				snippet.WriteString("LINK-NEEDS-REPLACED-BY-cluster_" + hash(trustBoundaryNested.Id))
				snippet.WriteString(";\n")
			}
			snippet.WriteString(" }\n\n")
			if drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
				snippet.WriteString(" }\n\n")
			}
		}
		subgraphSnippetsById[hash(trustBoundary.Id)] = snippet.String()
	}
	// here replace links and remove from map after replacement (i.e. move snippet into nested)
	for i := range subgraphSnippetsById {
		re := regexp.MustCompile(`LINK-NEEDS-REPLACED-BY-cluster_([0-9]*);`)
		for {
			matches := re.FindStringSubmatch(subgraphSnippetsById[i])
			if len(matches) > 0 {
				embeddedSnippet := " //nested:" + subgraphSnippetsById[matches[1]]
				subgraphSnippetsById[i] = strings.ReplaceAll(subgraphSnippetsById[i], matches[0], embeddedSnippet)
				subgraphSnippetsById[matches[1]] = "" // to something like remove it
			} else {
				break
			}
		}
	}
	// now write them all
	keys = make([]string, 0)
	for k := range subgraphSnippetsById {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		snippet := subgraphSnippetsById[key]
		dotContent.WriteString(snippet)
	}

	// Technical Assets ===============================================================================
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	// Convert map to slice of values:
	var techAssets []model.TechnicalAsset
	for _, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(model.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		dotContent.WriteString(makeTechAssetNode(technicalAsset, false))
		dotContent.WriteString("\n")
	}

	// Data Flows (Technical Communication Links) ===============================================================================
	for _, technicalAsset := range techAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			sourceId := technicalAsset.Id
			targetId := dataFlow.TargetId
			//log.Println("About to add link from", sourceId, "to", targetId, "with id", dataFlow.Id)
			var arrowStyle, arrowColor, readOrWriteHead, readOrWriteTail string
			if dataFlow.Readonly {
				readOrWriteHead = "empty"
				readOrWriteTail = "odot"
			} else {
				readOrWriteHead = "normal"
				readOrWriteTail = "dot"
			}
			dir := "forward"
			if dataFlow.IsBidirectional() {
				if !suppressBidirectionalArrows { // as it does not work as bug in graphviz with ortho: https://gitlab.com/graphviz/graphviz/issues/144
					dir = "both"
				}
			}
			arrowStyle = ` style="` + dataFlow.DetermineArrowLineStyle() + `" penwidth="` + dataFlow.DetermineArrowPenWidth() + `" arrowtail="` + readOrWriteTail + `" arrowhead="` + readOrWriteHead + `" dir="` + dir + `" arrowsize="2.0" `
			arrowColor = ` color="` + dataFlow.DetermineArrowColor() + `"`
			tweaks := ""
			if dataFlow.DiagramTweakWeight > 0 {
				tweaks += " weight=\"" + strconv.Itoa(dataFlow.DiagramTweakWeight) + "\" "
			}

			dotContent.WriteString("\n")
			dotContent.WriteString("  " + hash(sourceId) + " -> " + hash(targetId) +
				` [` + arrowColor + ` ` + arrowStyle + tweaks + ` constraint=` + strconv.FormatBool(dataFlow.DiagramTweakConstraint) + ` `)
			if !model.ParsedModelRoot.DiagramTweakSuppressEdgeLabels {
				dotContent.WriteString(` xlabel="` + encode(dataFlow.Protocol.String()) + `" fontcolor="` + dataFlow.DetermineLabelColor() + `" `)
			}
			dotContent.WriteString(" ];\n")
		}
	}

	dotContent.WriteString(makeDiagramInvisibleConnectionsTweaks())
	dotContent.WriteString(makeDiagramSameRankNodeTweaks())

	dotContent.WriteString("}")

	//fmt.Println(dotContent.String())

	// Write the DOT file
	file, err := os.Create(diagramFilenameDOT)
	checkErr(err)
	defer func() { _ = file.Close() }()
	_, err = fmt.Fprintln(file, dotContent.String())
	checkErr(err)
	return file
}

func makeDiagramInvisibleConnectionsTweaks() string {
	// see https://stackoverflow.com/questions/2476575/how-to-control-node-placement-in-graphviz-i-e-avoid-edge-crossings
	tweak := ""
	if len(model.ParsedModelRoot.DiagramTweakInvisibleConnectionsBetweenAssets) > 0 {
		for _, invisibleConnections := range model.ParsedModelRoot.DiagramTweakInvisibleConnectionsBetweenAssets {
			assetIDs := strings.Split(invisibleConnections, ":")
			if len(assetIDs) == 2 {
				checkTechnicalAssetExists(assetIDs[0], "diagram tweak connections", true)
				checkTechnicalAssetExists(assetIDs[1], "diagram tweak connections", true)
				tweak += "\n" + hash(assetIDs[0]) + " -> " + hash(assetIDs[1]) + " [style=invis]; \n"
			}
		}
	}
	return tweak
}

func makeDiagramSameRankNodeTweaks() string {
	// see https://stackoverflow.com/questions/25734244/how-do-i-place-nodes-on-the-same-level-in-dot
	tweak := ""
	if len(model.ParsedModelRoot.DiagramTweakSameRankAssets) > 0 {
		for _, sameRank := range model.ParsedModelRoot.DiagramTweakSameRankAssets {
			assetIDs := strings.Split(sameRank, ":")
			if len(assetIDs) > 0 {
				tweak += "{ rank=same; "
				for _, id := range assetIDs {
					checkTechnicalAssetExists(id, "diagram tweak same-rank", true)
					if len(model.ParsedModelRoot.TechnicalAssets[id].GetTrustBoundaryId()) > 0 {
						panic(errors.New("technical assets (referenced in same rank diagram tweak) are inside trust boundaries: " +
							fmt.Sprintf("%v", model.ParsedModelRoot.DiagramTweakSameRankAssets)))
					}
					tweak += " " + hash(id) + "; "
				}
				tweak += " }"
			}
		}
	}
	return tweak
}

func makeTechAssetNode(technicalAsset model.TechnicalAsset, simplified bool) string {
	if simplified {
		color := colors.RgbHexColorOutOfScope()
		if !technicalAsset.OutOfScope {
			risks := technicalAsset.GeneratedRisks()
			switch model.HighestSeverityStillAtRisk(risks) {
			case model.CriticalSeverity:
				color = colors.RgbHexColorCriticalRisk()
			case model.HighSeverity:
				color = colors.RgbHexColorHighRisk()
			case model.ElevatedSeverity:
				color = colors.RgbHexColorElevatedRisk()
			case model.MediumSeverity:
				color = colors.RgbHexColorMediumRisk()
			case model.LowSeverity:
				color = colors.RgbHexColorLowRisk()
			default:
				color = "#444444" // since black is too dark here as fill color
			}
			if len(model.ReduceToOnlyStillAtRisk(risks)) == 0 {
				color = "#444444" // since black is too dark here as fill color
			}
		}
		return "  " + hash(technicalAsset.Id) + ` [ shape="box" style="filled" fillcolor="` + color + `"
				label=<<b>` + encode(technicalAsset.Title) + `</b>> penwidth="3.0" color="` + color + `" ];
				`
	} else {
		var shape, title string
		var lineBreak = ""
		switch technicalAsset.Type {
		case model.ExternalEntity:
			shape = "box"
			title = technicalAsset.Title
		case model.Process:
			shape = "ellipse"
			title = technicalAsset.Title
		case model.Datastore:
			shape = "cylinder"
			title = technicalAsset.Title
			if technicalAsset.Redundant {
				lineBreak = "<br/>"
			}
		}

		if technicalAsset.UsedAsClientByHuman {
			shape = "octagon"
		}

		// RAA = Relative Attacker Attractiveness
		raa := technicalAsset.RAA
		var attackerAttractivenessLabel string
		if technicalAsset.OutOfScope {
			attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: out of scope</font>"
		} else {
			attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: " + fmt.Sprintf("%.0f", raa) + " %</font>"
		}

		compartmentBorder := "0"
		if technicalAsset.MultiTenant {
			compartmentBorder = "1"
		}

		return "  " + hash(technicalAsset.Id) + ` [
	label=<<table border="0" cellborder="` + compartmentBorder + `" cellpadding="2" cellspacing="0"><tr><td><font point-size="15" color="` + colors.DarkBlue + `">` + lineBreak + technicalAsset.Technology.String() + `</font><br/><font point-size="15" color="` + colors.LightGray + `">` + technicalAsset.Size.String() + `</font></td></tr><tr><td><b><font color="` + technicalAsset.DetermineLabelColor() + `">` + encode(title) + `</font></b><br/></td></tr><tr><td>` + attackerAttractivenessLabel + `</td></tr></table>>
	shape=` + shape + ` style="` + technicalAsset.DetermineShapeBorderLineStyle() + `,` + technicalAsset.DetermineShapeStyle() + `" penwidth="` + technicalAsset.DetermineShapeBorderPenWidth() + `" fillcolor="` + technicalAsset.DetermineShapeFillColor() + `"
	peripheries=` + strconv.Itoa(technicalAsset.DetermineShapePeripheries()) + `
	color="` + technicalAsset.DetermineShapeBorderColor() + "\"\n  ]; "
	}
}

func makeDataAssetNode(dataAsset model.DataAsset) string {
	var color string
	switch dataAsset.IdentifiedDataBreachProbabilityStillAtRisk() {
	case model.Probable:
		color = colors.RgbHexColorHighRisk()
	case model.Possible:
		color = colors.RgbHexColorMediumRisk()
	case model.Improbable:
		color = colors.RgbHexColorLowRisk()
	default:
		color = "#444444" // since black is too dark here as fill color
	}
	if !dataAsset.IsDataBreachPotentialStillAtRisk() {
		color = "#444444" // since black is too dark here as fill color
	}
	return "  " + hash(dataAsset.Id) + ` [ label=<<b>` + encode(dataAsset.Title) + `</b>> penwidth="3.0" style="filled" fillcolor="` + color + `" color="` + color + "\"\n  ]; "
}

func encode(value string) string {
	return strings.ReplaceAll(value, "&", "&amp;")
}

func renderDataFlowDiagramGraphvizImage(dotFile *os.File, targetDir string) {
	if *verbose {
		fmt.Println("Rendering data flow diagram input")
	}
	// tmp files
	tmpFileDOT, err := os.CreateTemp(model.TempFolder, "diagram-*-.gv")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFileDOT.Name()) }()

	tmpFilePNG, err := os.CreateTemp(model.TempFolder, "diagram-*-.png")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()

	// copy into tmp file as input
	input, err := os.ReadFile(dotFile.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(tmpFileDOT.Name(), input, 0644)
	if err != nil {
		fmt.Println("Error creating", tmpFileDOT.Name())
		fmt.Println(err)
		return
	}

	// exec
	cmd := exec.Command(graphvizDataFlowDiagramConversionCall, tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(errors.New("graph rendering call failed with error:" + err.Error()))
	}
	// copy into resulting file
	input, err = os.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(targetDir+"/"+dataFlowDiagramFilenamePNG, input, 0644)
	if err != nil {
		fmt.Println("Error creating", dataFlowDiagramFilenamePNG)
		fmt.Println(err)
		return
	}
}

func renderDataAssetDiagramGraphvizImage(dotFile *os.File, targetDir string) { // TODO dedupe with other render...() method here
	if *verbose {
		fmt.Println("Rendering data asset diagram input")
	}
	// tmp files
	tmpFileDOT, err := os.CreateTemp(model.TempFolder, "diagram-*-.gv")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFileDOT.Name()) }()

	tmpFilePNG, err := os.CreateTemp(model.TempFolder, "diagram-*-.png")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()

	// copy into tmp file as input
	input, err := os.ReadFile(dotFile.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(tmpFileDOT.Name(), input, 0644)
	if err != nil {
		fmt.Println("Error creating", tmpFileDOT.Name())
		fmt.Println(err)
		return
	}

	// exec
	cmd := exec.Command(graphvizDataAssetDiagramConversionCall, tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(errors.New("graph rendering call failed with error: " + err.Error()))
	}
	// copy into resulting file
	input, err = os.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(targetDir+"/"+dataAssetDiagramFilenamePNG, input, 0644)
	if err != nil {
		fmt.Println("Error creating", dataAssetDiagramFilenamePNG)
		fmt.Println(err)
		return
	}
}
