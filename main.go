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
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/threagile/threagile/colors"
	"github.com/threagile/threagile/macros/built-in/add-build-pipeline"
	"github.com/threagile/threagile/macros/built-in/add-vault"
	"github.com/threagile/threagile/macros/built-in/pretty-print"
	"github.com/threagile/threagile/macros/built-in/remove-unused-tags"
	"github.com/threagile/threagile/macros/built-in/seed-risk-tracking"
	"github.com/threagile/threagile/macros/built-in/seed-tags"
	"github.com/threagile/threagile/model"
	"github.com/threagile/threagile/report"
	"github.com/threagile/threagile/risks/built-in/accidental-secret-leak"
	"github.com/threagile/threagile/risks/built-in/code-backdooring"
	"github.com/threagile/threagile/risks/built-in/container-baseimage-backdooring"
	"github.com/threagile/threagile/risks/built-in/container-platform-escape"
	"github.com/threagile/threagile/risks/built-in/cross-site-request-forgery"
	"github.com/threagile/threagile/risks/built-in/cross-site-scripting"
	"github.com/threagile/threagile/risks/built-in/dos-risky-access-across-trust-boundary"
	"github.com/threagile/threagile/risks/built-in/incomplete-model"
	"github.com/threagile/threagile/risks/built-in/ldap-injection"
	"github.com/threagile/threagile/risks/built-in/missing-authentication"
	"github.com/threagile/threagile/risks/built-in/missing-authentication-second-factor"
	"github.com/threagile/threagile/risks/built-in/missing-build-infrastructure"
	"github.com/threagile/threagile/risks/built-in/missing-cloud-hardening"
	"github.com/threagile/threagile/risks/built-in/missing-file-validation"
	"github.com/threagile/threagile/risks/built-in/missing-hardening"
	"github.com/threagile/threagile/risks/built-in/missing-identity-propagation"
	"github.com/threagile/threagile/risks/built-in/missing-identity-provider-isolation"
	"github.com/threagile/threagile/risks/built-in/missing-identity-store"
	"github.com/threagile/threagile/risks/built-in/missing-network-segmentation"
	"github.com/threagile/threagile/risks/built-in/missing-vault"
	"github.com/threagile/threagile/risks/built-in/missing-vault-isolation"
	"github.com/threagile/threagile/risks/built-in/missing-waf"
	"github.com/threagile/threagile/risks/built-in/mixed-targets-on-shared-runtime"
	"github.com/threagile/threagile/risks/built-in/path-traversal"
	"github.com/threagile/threagile/risks/built-in/push-instead-of-pull-deployment"
	"github.com/threagile/threagile/risks/built-in/search-query-injection"
	"github.com/threagile/threagile/risks/built-in/server-side-request-forgery"
	"github.com/threagile/threagile/risks/built-in/service-registry-poisoning"
	"github.com/threagile/threagile/risks/built-in/sql-nosql-injection"
	"github.com/threagile/threagile/risks/built-in/unchecked-deployment"
	"github.com/threagile/threagile/risks/built-in/unencrypted-asset"
	"github.com/threagile/threagile/risks/built-in/unencrypted-communication"
	"github.com/threagile/threagile/risks/built-in/unguarded-access-from-internet"
	"github.com/threagile/threagile/risks/built-in/unguarded-direct-datastore-access"
	"github.com/threagile/threagile/risks/built-in/unnecessary-communication-link"
	"github.com/threagile/threagile/risks/built-in/unnecessary-data-asset"
	"github.com/threagile/threagile/risks/built-in/unnecessary-data-transfer"
	"github.com/threagile/threagile/risks/built-in/unnecessary-technical-asset"
	"github.com/threagile/threagile/risks/built-in/untrusted-deserialization"
	"github.com/threagile/threagile/risks/built-in/wrong-communication-link-content"
	"github.com/threagile/threagile/risks/built-in/wrong-trust-boundary-content"
	"github.com/threagile/threagile/risks/built-in/xml-external-entity"
	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
	"hash/fnv"
	"io"
	"io/ioutil"
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

	if _, ok := skippedRules[unencrypted_asset.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unencrypted_asset.Category().Id)
		delete(skippedRules, unencrypted_asset.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unencrypted_asset.SupportedTags())
		risks := unencrypted_asset.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unencrypted_asset.Category()] = risks
		}
	}

	if _, ok := skippedRules[unencrypted_communication.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unencrypted_communication.Category().Id)
		delete(skippedRules, unencrypted_communication.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unencrypted_communication.SupportedTags())
		risks := unencrypted_communication.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unencrypted_communication.Category()] = risks
		}
	}

	if _, ok := skippedRules[unguarded_direct_datastore_access.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unguarded_direct_datastore_access.Category().Id)
		delete(skippedRules, unguarded_direct_datastore_access.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unguarded_direct_datastore_access.SupportedTags())
		risks := unguarded_direct_datastore_access.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unguarded_direct_datastore_access.Category()] = risks
		}
	}

	if _, ok := skippedRules[unguarded_access_from_internet.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unguarded_access_from_internet.Category().Id)
		delete(skippedRules, unguarded_access_from_internet.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unguarded_access_from_internet.SupportedTags())
		risks := unguarded_access_from_internet.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unguarded_access_from_internet.Category()] = risks
		}
	}

	if _, ok := skippedRules[dos_risky_access_across_trust_boundary.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", dos_risky_access_across_trust_boundary.Category().Id)
		delete(skippedRules, dos_risky_access_across_trust_boundary.Category().Id)
	} else {
		model.AddToListOfSupportedTags(dos_risky_access_across_trust_boundary.SupportedTags())
		risks := dos_risky_access_across_trust_boundary.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[dos_risky_access_across_trust_boundary.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_network_segmentation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_network_segmentation.Category().Id)
		delete(skippedRules, missing_network_segmentation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_network_segmentation.SupportedTags())
		risks := missing_network_segmentation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_network_segmentation.Category()] = risks
		}
	}

	if _, ok := skippedRules[mixed_targets_on_shared_runtime.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", mixed_targets_on_shared_runtime.Category().Id)
		delete(skippedRules, mixed_targets_on_shared_runtime.Category().Id)
	} else {
		model.AddToListOfSupportedTags(mixed_targets_on_shared_runtime.SupportedTags())
		risks := mixed_targets_on_shared_runtime.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[mixed_targets_on_shared_runtime.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_identity_propagation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_identity_propagation.Category().Id)
		delete(skippedRules, missing_identity_propagation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_identity_propagation.SupportedTags())
		risks := missing_identity_propagation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_identity_propagation.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_identity_store.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_identity_store.Category().Id)
		delete(skippedRules, missing_identity_store.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_identity_store.SupportedTags())
		risks := missing_identity_store.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_identity_store.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_authentication.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_authentication.Category().Id)
		delete(skippedRules, missing_authentication.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_authentication.SupportedTags())
		risks := missing_authentication.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_authentication.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_authentication_second_factor.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_authentication_second_factor.Category().Id)
		delete(skippedRules, missing_authentication_second_factor.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_authentication_second_factor.SupportedTags())
		risks := missing_authentication_second_factor.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_authentication_second_factor.Category()] = risks
		}
	}

	if _, ok := skippedRules[unnecessary_data_transfer.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unnecessary_data_transfer.Category().Id)
		delete(skippedRules, unnecessary_data_transfer.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unnecessary_data_transfer.SupportedTags())
		risks := unnecessary_data_transfer.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unnecessary_data_transfer.Category()] = risks
		}
	}

	if _, ok := skippedRules[unnecessary_communication_link.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unnecessary_communication_link.Category().Id)
		delete(skippedRules, unnecessary_communication_link.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unnecessary_communication_link.SupportedTags())
		risks := unnecessary_communication_link.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unnecessary_communication_link.Category()] = risks
		}
	}

	if _, ok := skippedRules[unnecessary_technical_asset.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unnecessary_technical_asset.Category().Id)
		delete(skippedRules, unnecessary_technical_asset.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unnecessary_technical_asset.SupportedTags())
		risks := unnecessary_technical_asset.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unnecessary_technical_asset.Category()] = risks
		}
	}

	if _, ok := skippedRules[unnecessary_data_asset.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unnecessary_data_asset.Category().Id)
		delete(skippedRules, unnecessary_data_asset.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unnecessary_data_asset.SupportedTags())
		risks := unnecessary_data_asset.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unnecessary_data_asset.Category()] = risks
		}
	}

	if _, ok := skippedRules[sql_nosql_injection.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", sql_nosql_injection.Category().Id)
		delete(skippedRules, sql_nosql_injection.Category().Id)
	} else {
		model.AddToListOfSupportedTags(sql_nosql_injection.SupportedTags())
		risks := sql_nosql_injection.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[sql_nosql_injection.Category()] = risks
		}
	}

	if _, ok := skippedRules[ldap_injection.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", ldap_injection.Category().Id)
		delete(skippedRules, ldap_injection.Category().Id)
	} else {
		model.AddToListOfSupportedTags(ldap_injection.SupportedTags())
		risks := ldap_injection.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[ldap_injection.Category()] = risks
		}
	}

	if _, ok := skippedRules[cross_site_scripting.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", cross_site_scripting.Category().Id)
		delete(skippedRules, cross_site_scripting.Category().Id)
	} else {
		model.AddToListOfSupportedTags(cross_site_scripting.SupportedTags())
		risks := cross_site_scripting.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[cross_site_scripting.Category()] = risks
		}
	}

	if _, ok := skippedRules[cross_site_request_forgery.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", cross_site_request_forgery.Category().Id)
		delete(skippedRules, cross_site_request_forgery.Category().Id)
	} else {
		model.AddToListOfSupportedTags(cross_site_request_forgery.SupportedTags())
		risks := cross_site_request_forgery.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[cross_site_request_forgery.Category()] = risks
		}
	}

	if _, ok := skippedRules[server_side_request_forgery.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", server_side_request_forgery.Category().Id)
		delete(skippedRules, server_side_request_forgery.Category().Id)
	} else {
		model.AddToListOfSupportedTags(server_side_request_forgery.SupportedTags())
		risks := server_side_request_forgery.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[server_side_request_forgery.Category()] = risks
		}
	}

	if _, ok := skippedRules[path_traversal.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", path_traversal.Category().Id)
		delete(skippedRules, path_traversal.Category().Id)
	} else {
		model.AddToListOfSupportedTags(path_traversal.SupportedTags())
		risks := path_traversal.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[path_traversal.Category()] = risks
		}
	}

	if _, ok := skippedRules[push_instead_of_pull_deployment.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", push_instead_of_pull_deployment.Category().Id)
		delete(skippedRules, push_instead_of_pull_deployment.Category().Id)
	} else {
		model.AddToListOfSupportedTags(push_instead_of_pull_deployment.SupportedTags())
		risks := push_instead_of_pull_deployment.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[push_instead_of_pull_deployment.Category()] = risks
		}
	}

	if _, ok := skippedRules[search_query_injection.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", search_query_injection.Category().Id)
		delete(skippedRules, search_query_injection.Category().Id)
	} else {
		model.AddToListOfSupportedTags(search_query_injection.SupportedTags())
		risks := search_query_injection.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[search_query_injection.Category()] = risks
		}
	}

	if _, ok := skippedRules[service_registry_poisoning.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", service_registry_poisoning.Category().Id)
		delete(skippedRules, service_registry_poisoning.Category().Id)
	} else {
		model.AddToListOfSupportedTags(service_registry_poisoning.SupportedTags())
		risks := service_registry_poisoning.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[service_registry_poisoning.Category()] = risks
		}
	}

	if _, ok := skippedRules[untrusted_deserialization.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", untrusted_deserialization.Category().Id)
		delete(skippedRules, untrusted_deserialization.Category().Id)
	} else {
		model.AddToListOfSupportedTags(untrusted_deserialization.SupportedTags())
		risks := untrusted_deserialization.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[untrusted_deserialization.Category()] = risks
		}
	}

	if _, ok := skippedRules[xml_external_entity.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", xml_external_entity.Category().Id)
		delete(skippedRules, xml_external_entity.Category().Id)
	} else {
		model.AddToListOfSupportedTags(xml_external_entity.SupportedTags())
		risks := xml_external_entity.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[xml_external_entity.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_cloud_hardening.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_cloud_hardening.Category().Id)
		delete(skippedRules, missing_cloud_hardening.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_cloud_hardening.SupportedTags())
		risks := missing_cloud_hardening.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_cloud_hardening.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_file_validation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_file_validation.Category().Id)
		delete(skippedRules, missing_file_validation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_file_validation.SupportedTags())
		risks := missing_file_validation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_file_validation.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_hardening.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_hardening.Category().Id)
		delete(skippedRules, missing_hardening.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_hardening.SupportedTags())
		risks := missing_hardening.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_hardening.Category()] = risks
		}
	}

	if _, ok := skippedRules[accidental_secret_leak.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", accidental_secret_leak.Category().Id)
		delete(skippedRules, accidental_secret_leak.Category().Id)
	} else {
		model.AddToListOfSupportedTags(accidental_secret_leak.SupportedTags())
		risks := accidental_secret_leak.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[accidental_secret_leak.Category()] = risks
		}
	}

	if _, ok := skippedRules[code_backdooring.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", code_backdooring.Category().Id)
		delete(skippedRules, code_backdooring.Category().Id)
	} else {
		model.AddToListOfSupportedTags(code_backdooring.SupportedTags())
		risks := code_backdooring.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[code_backdooring.Category()] = risks
		}
	}

	if _, ok := skippedRules[container_baseimage_backdooring.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", container_baseimage_backdooring.Category().Id)
		delete(skippedRules, container_baseimage_backdooring.Category().Id)
	} else {
		model.AddToListOfSupportedTags(container_baseimage_backdooring.SupportedTags())
		risks := container_baseimage_backdooring.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[container_baseimage_backdooring.Category()] = risks
		}
	}

	if _, ok := skippedRules[container_platform_escape.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", container_platform_escape.Category().Id)
		delete(skippedRules, container_platform_escape.Category().Id)
	} else {
		model.AddToListOfSupportedTags(container_platform_escape.SupportedTags())
		risks := container_platform_escape.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[container_platform_escape.Category()] = risks
		}
	}

	if _, ok := skippedRules[incomplete_model.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", incomplete_model.Category().Id)
		delete(skippedRules, incomplete_model.Category().Id)
	} else {
		model.AddToListOfSupportedTags(incomplete_model.SupportedTags())
		risks := incomplete_model.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[incomplete_model.Category()] = risks
		}
	}

	if _, ok := skippedRules[unchecked_deployment.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", unchecked_deployment.Category().Id)
		delete(skippedRules, unchecked_deployment.Category().Id)
	} else {
		model.AddToListOfSupportedTags(unchecked_deployment.SupportedTags())
		risks := unchecked_deployment.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[unchecked_deployment.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_build_infrastructure.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_build_infrastructure.Category().Id)
		delete(skippedRules, missing_build_infrastructure.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_build_infrastructure.SupportedTags())
		risks := missing_build_infrastructure.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_build_infrastructure.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_identity_provider_isolation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_identity_provider_isolation.Category().Id)
		delete(skippedRules, missing_identity_provider_isolation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_identity_provider_isolation.SupportedTags())
		risks := missing_identity_provider_isolation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_identity_provider_isolation.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_vault.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_vault.Category().Id)
		delete(skippedRules, missing_vault.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_vault.SupportedTags())
		risks := missing_vault.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_vault.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_vault_isolation.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_vault_isolation.Category().Id)
		delete(skippedRules, missing_vault_isolation.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_vault_isolation.SupportedTags())
		risks := missing_vault_isolation.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_vault_isolation.Category()] = risks
		}
	}

	if _, ok := skippedRules[missing_waf.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", missing_waf.Category().Id)
		delete(skippedRules, missing_waf.Category().Id)
	} else {
		model.AddToListOfSupportedTags(missing_waf.SupportedTags())
		risks := missing_waf.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[missing_waf.Category()] = risks
		}
	}

	if _, ok := skippedRules[wrong_communication_link_content.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", wrong_communication_link_content.Category().Id)
		delete(skippedRules, wrong_communication_link_content.Category().Id)
	} else {
		model.AddToListOfSupportedTags(wrong_communication_link_content.SupportedTags())
		risks := wrong_communication_link_content.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[wrong_communication_link_content.Category()] = risks
		}
	}

	if _, ok := skippedRules[wrong_trust_boundary_content.Category().Id]; ok {
		fmt.Println("Skipping risk rule:", wrong_trust_boundary_content.Category().Id)
		delete(skippedRules, wrong_trust_boundary_content.Category().Id)
	} else {
		model.AddToListOfSupportedTags(wrong_trust_boundary_content.SupportedTags())
		risks := wrong_trust_boundary_content.GenerateRisks()
		if len(risks) > 0 {
			model.GeneratedRisksByCategory[wrong_trust_boundary_content.Category()] = risks
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
	for category, _ := range model.GeneratedRisksByCategory {
		for i, _ := range model.GeneratedRisksByCategory[category] {
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
	defer r.Close()

	for _, f := range r.File {
		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)
		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}
		filenames = append(filenames, fpath)
		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}
		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		_, err = io.Copy(outFile, rc)
		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()
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
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

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
	defer fileToZip.Close()

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
			os.Stderr.WriteString(err.Error() + "\n")
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
		case add_build_pipeline.GetMacroDetails().ID:
			macroDetails = add_build_pipeline.GetMacroDetails()
		case add_vault.GetMacroDetails().ID:
			macroDetails = add_vault.GetMacroDetails()
		case pretty_print.GetMacroDetails().ID:
			macroDetails = pretty_print.GetMacroDetails()
		case remove_unused_tags.GetMacroDetails().ID:
			macroDetails = remove_unused_tags.GetMacroDetails()
		case seed_risk_tracking.GetMacroDetails().ID:
			macroDetails = seed_risk_tracking.GetMacroDetails()
		case seed_tags.GetMacroDetails().ID:
			macroDetails = seed_tags.GetMacroDetails()
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
			case add_build_pipeline.GetMacroDetails().ID:
				nextQuestion, err = add_build_pipeline.GetNextQuestion()
			case add_vault.GetMacroDetails().ID:
				nextQuestion, err = add_vault.GetNextQuestion()
			case pretty_print.GetMacroDetails().ID:
				nextQuestion, err = pretty_print.GetNextQuestion()
			case remove_unused_tags.GetMacroDetails().ID:
				nextQuestion, err = remove_unused_tags.GetNextQuestion()
			case seed_risk_tracking.GetMacroDetails().ID:
				nextQuestion, err = seed_risk_tracking.GetNextQuestion()
			case seed_tags.GetMacroDetails().ID:
				nextQuestion, err = seed_tags.GetNextQuestion()
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
					selectedValues := make(map[string]bool, 0)
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
					case add_build_pipeline.GetMacroDetails().ID:
						message, validResult, err = add_build_pipeline.GoBack()
					case add_vault.GetMacroDetails().ID:
						message, validResult, err = add_vault.GoBack()
					case pretty_print.GetMacroDetails().ID:
						message, validResult, err = pretty_print.GoBack()
					case remove_unused_tags.GetMacroDetails().ID:
						message, validResult, err = remove_unused_tags.GoBack()
					case seed_risk_tracking.GetMacroDetails().ID:
						message, validResult, err = seed_risk_tracking.GoBack()
					case seed_tags.GetMacroDetails().ID:
						message, validResult, err = seed_tags.GoBack()
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
					case add_build_pipeline.GetMacroDetails().ID:
						message, validResult, err = add_build_pipeline.ApplyAnswer(nextQuestion.ID, answer)
					case add_vault.GetMacroDetails().ID:
						message, validResult, err = add_vault.ApplyAnswer(nextQuestion.ID, answer)
					case pretty_print.GetMacroDetails().ID:
						message, validResult, err = pretty_print.ApplyAnswer(nextQuestion.ID, answer)
					case remove_unused_tags.GetMacroDetails().ID:
						message, validResult, err = remove_unused_tags.ApplyAnswer(nextQuestion.ID, answer)
					case seed_risk_tracking.GetMacroDetails().ID:
						message, validResult, err = seed_risk_tracking.ApplyAnswer(nextQuestion.ID, answer)
					case seed_tags.GetMacroDetails().ID:
						message, validResult, err = seed_tags.ApplyAnswer(nextQuestion.ID, answer)
					}
				}
			} else {
				switch macroDetails.ID {
				case add_build_pipeline.GetMacroDetails().ID:
					message, validResult, err = add_build_pipeline.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case add_vault.GetMacroDetails().ID:
					message, validResult, err = add_vault.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case pretty_print.GetMacroDetails().ID:
					message, validResult, err = pretty_print.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case remove_unused_tags.GetMacroDetails().ID:
					message, validResult, err = remove_unused_tags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case seed_risk_tracking.GetMacroDetails().ID:
					message, validResult, err = seed_risk_tracking.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case seed_tags.GetMacroDetails().ID:
					message, validResult, err = seed_tags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
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
			case add_build_pipeline.GetMacroDetails().ID:
				changes, message, validResult, err = add_build_pipeline.GetFinalChangeImpact(&modelInput)
			case add_vault.GetMacroDetails().ID:
				changes, message, validResult, err = add_vault.GetFinalChangeImpact(&modelInput)
			case pretty_print.GetMacroDetails().ID:
				changes, message, validResult, err = pretty_print.GetFinalChangeImpact(&modelInput)
			case remove_unused_tags.GetMacroDetails().ID:
				changes, message, validResult, err = remove_unused_tags.GetFinalChangeImpact(&modelInput)
			case seed_risk_tracking.GetMacroDetails().ID:
				changes, message, validResult, err = seed_risk_tracking.GetFinalChangeImpact(&modelInput)
			case seed_tags.GetMacroDetails().ID:
				changes, message, validResult, err = seed_tags.GetFinalChangeImpact(&modelInput)
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
				case add_build_pipeline.GetMacroDetails().ID:
					message, validResult, err = add_build_pipeline.Execute(&modelInput)
				case add_vault.GetMacroDetails().ID:
					message, validResult, err = add_vault.Execute(&modelInput)
				case pretty_print.GetMacroDetails().ID:
					message, validResult, err = pretty_print.Execute(&modelInput)
				case remove_unused_tags.GetMacroDetails().ID:
					message, validResult, err = remove_unused_tags.Execute(&modelInput)
				case seed_risk_tracking.GetMacroDetails().ID:
					message, validResult, err = seed_risk_tracking.Execute(&modelInput)
				case seed_tags.GetMacroDetails().ID:
					message, validResult, err = seed_tags.Execute(&modelInput)
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
				err = ioutil.WriteFile(inputFilename, yamlBytes, 0400)
				checkErr(err)
				fmt.Println("Model file successfully updated")
				return
			} else if answer == "no" || answer == "n" {
				fmt.Println("Quitting without executing the model macro")
				return
			}
		}
		fmt.Println()
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
			tmpFileGV, err := ioutil.TempFile(model.TempFolder, dataFlowDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFileGV.Name()
			defer os.Remove(gvFile)
		}
		dotFile := writeDataFlowDiagramGraphvizDOT(gvFile, *diagramDPI)
		renderDataFlowDiagramGraphvizImage(dotFile, outputDirectory)
	}
	// Data Asset Diagram rendering
	if renderDataAssetDiagram {
		gvFile := outputDirectory + "/" + dataAssetDiagramFilenameDOT
		if !keepDiagramSourceFiles {
			tmpFile, err := ioutil.TempFile(model.TempFolder, dataAssetDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFile.Name()
			defer os.Remove(gvFile)
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
		defer f.Close()
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
	// determine plugin to load
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
	customRiskRules = make(map[string]model.CustomRiskRule, 0)
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

	tmpInputDir, err := ioutil.TempDir(model.TempFolder, "threagile-input-")
	checkErr(err)
	defer os.RemoveAll(tmpInputDir)

	tmpModelFile, err := ioutil.TempFile(tmpInputDir, "threagile-model-*")
	checkErr(err)
	defer os.Remove(tmpModelFile.Name())
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

	tmpOutputDir, err := ioutil.TempDir(model.TempFolder, "threagile-output-")
	checkErr(err)
	defer os.RemoveAll(tmpOutputDir)

	tmpResultFile, err := ioutil.TempFile(model.TempFolder, "threagile-result-*.zip")
	checkErr(err)
	defer os.Remove(tmpResultFile.Name())

	if dryRun {
		doItViaRuntimeCall(yamlFile, tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, false, true, true, true, 40)
	} else {
		doItViaRuntimeCall(yamlFile, tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, true, true, true, true, true, true, true, true, dpi)
	}
	checkErr(err)

	yamlContent, err = ioutil.ReadFile(yamlFile)
	checkErr(err)
	err = ioutil.WriteFile(tmpOutputDir+"/threagile.yaml", yamlContent, 0400)
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
	router.Run(":" + strconv.Itoa(*serverPort)) // listen and serve on 0.0.0.0:8080 or whatever port was specified
}

func exampleFile(context *gin.Context) {
	example, err := ioutil.ReadFile("/app/threagile-example-model.yaml")
	checkErr(err)
	context.Data(http.StatusOK, gin.MIMEYAML, example)
}

func stubFile(context *gin.Context) {
	stub, err := ioutil.ReadFile("/app/threagile-stub-model.yaml")
	checkErr(err)
	context.Data(http.StatusOK, gin.MIMEYAML, addSupportedTags(stub)) // TODO use also the MIMEYAML way of serving YAML in model export?
}

func addSupportedTags(input []byte) []byte {
	// add distinct tags as "tags_available"
	supportedTags := make(map[string]bool, 0)
	for _, customRule := range customRiskRules {
		for _, tag := range customRule.SupportedTags() {
			supportedTags[strings.ToLower(tag)] = true
		}
	}
	for _, tag := range accidental_secret_leak.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range code_backdooring.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range container_baseimage_backdooring.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range container_platform_escape.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range cross_site_request_forgery.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range cross_site_scripting.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range dos_risky_access_across_trust_boundary.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range incomplete_model.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range ldap_injection.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_authentication.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_authentication_second_factor.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_build_infrastructure.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_cloud_hardening.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_file_validation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_hardening.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_identity_propagation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_identity_provider_isolation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_identity_store.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_network_segmentation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_vault.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_vault_isolation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missing_waf.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range mixed_targets_on_shared_runtime.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range path_traversal.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range push_instead_of_pull_deployment.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range search_query_injection.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range server_side_request_forgery.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range service_registry_poisoning.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range sql_nosql_injection.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unchecked_deployment.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unencrypted_asset.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unencrypted_communication.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unguarded_access_from_internet.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unguarded_direct_datastore_access.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessary_communication_link.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessary_data_asset.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessary_data_transfer.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessary_technical_asset.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range untrusted_deserialization.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range wrong_communication_link_content.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range wrong_trust_boundary_content.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range xml_external_entity.SupportedTags() {
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
	xorRand                              []byte
	createdNanotime, lastAcessedNanotime int64
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
		xorRand:             xorBytesArr,
		createdNanotime:     now,
		lastAcessedNanotime: now,
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
			if now-val.lastAcessedNanotime > 60000000000 || now-val.createdNanotime > 180000000000 {
				fmt.Println("About to remove a token hash from maps")
				deleteTokenHashFromMaps(tokenHash)
			}
		} else {
			// remove all elements older than 30 minutes (= 1800000000000 ns) soft
			// and all elements older than 10 hours (= 36000000000000 ns) hard
			if now-val.lastAcessedNanotime > 1800000000000 || now-val.createdNanotime > 36000000000000 {
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
	tmpModelFile, err := ioutil.TempFile(model.TempFolder, "threagile-direct-analyze-*")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer os.Remove(tmpModelFile.Name())
	tmpOutputDir, err := ioutil.TempDir(model.TempFolder, "threagile-direct-analyze-")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer os.RemoveAll(tmpOutputDir)
	tmpResultFile, err := ioutil.TempFile(model.TempFolder, "threagile-result-*.zip")
	checkErr(err)
	defer os.Remove(tmpResultFile.Name())

	err = ioutil.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)

	doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *riskRulesPlugins, *skipRiskRules, *ignoreOrphanedRiskTracking, true, true, true, true, true, true, true, true, dpi)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	err = ioutil.WriteFile(tmpOutputDir+"/threagile.yaml", []byte(yamlText), 0400)
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
	tmpModelFile, err := ioutil.TempFile(model.TempFolder, "threagile-render-*")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer os.Remove(tmpModelFile.Name())
	tmpOutputDir, err := ioutil.TempDir(model.TempFolder, "threagile-render-")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer os.RemoveAll(tmpOutputDir)
	err = ioutil.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)
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
		json, err := ioutil.ReadFile(tmpOutputDir + "/" + jsonRisksFilename)
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
		json, err := ioutil.ReadFile(tmpOutputDir + "/" + jsonTechnicalAssetsFilename)
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
		json, err := ioutil.ReadFile(tmpOutputDir + "/" + jsonStatsFilename)
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

	uuid := context.Param("model-id") // UUID is syntactically validated in readModel+checkModelFolder (next line) via uuid.Parse(modelUUID)
	_, _, ok = readModel(context, uuid, key, folderNameOfKey)
	if ok {
		// first analyze it simply by executing the full risk process (just discard the result) to ensure that everything would work
		yamlContent, ok := execute(context, true)
		if ok {
			// if we're here, then no problem was raised, so ok to proceed
			ok = writeModelYAML(context, string(yamlContent), key, folderNameForModel(folderNameOfKey, uuid), "Model Import", false)
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
	keyFolders, err := ioutil.ReadDir(baseFolder)
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
			modelFolders, err := ioutil.ReadDir(baseFolder + "/" + keyFolder.Name())
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
		for title, dataAsset := range modelInput.Data_assets {
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
		for title, dataAsset := range modelInput.Data_assets {
			if dataAsset.ID == context.Param("data-asset-id") {
				// also remove all usages of this data asset !!
				for _, techAsset := range modelInput.Technical_assets {
					if techAsset.Data_assets_processed != nil {
						for i, parsedChangeCandidateAsset := range techAsset.Data_assets_processed {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.Data_assets_processed[i:], techAsset.Data_assets_processed[i+1:])                           // Shift a[i+1:] left one index.
								techAsset.Data_assets_processed[len(techAsset.Data_assets_processed)-1] = ""                               // Erase last element (write zero value).
								techAsset.Data_assets_processed = techAsset.Data_assets_processed[:len(techAsset.Data_assets_processed)-1] // Truncate slice.
							}
						}
					}
					if techAsset.Data_assets_stored != nil {
						for i, parsedChangeCandidateAsset := range techAsset.Data_assets_stored {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.Data_assets_stored[i:], techAsset.Data_assets_stored[i+1:])                        // Shift a[i+1:] left one index.
								techAsset.Data_assets_stored[len(techAsset.Data_assets_stored)-1] = ""                            // Erase last element (write zero value).
								techAsset.Data_assets_stored = techAsset.Data_assets_stored[:len(techAsset.Data_assets_stored)-1] // Truncate slice.
							}
						}
					}
					if techAsset.Communication_links != nil {
						for title, commLink := range techAsset.Communication_links {
							for i, dataAssetSent := range commLink.Data_assets_sent {
								referencedAsset := fmt.Sprintf("%v", dataAssetSent)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.Communication_links[title].Data_assets_sent[i:], techAsset.Communication_links[title].Data_assets_sent[i+1:]) // Shift a[i+1:] left one index.
									techAsset.Communication_links[title].Data_assets_sent[len(techAsset.Communication_links[title].Data_assets_sent)-1] = ""     // Erase last element (write zero value).
									x := techAsset.Communication_links[title]
									x.Data_assets_sent = techAsset.Communication_links[title].Data_assets_sent[:len(techAsset.Communication_links[title].Data_assets_sent)-1] // Truncate slice.
									techAsset.Communication_links[title] = x
								}
							}
							for i, dataAssetReceived := range commLink.Data_assets_received {
								referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.Communication_links[title].Data_assets_received[i:], techAsset.Communication_links[title].Data_assets_received[i+1:]) // Shift a[i+1:] left one index.
									techAsset.Communication_links[title].Data_assets_received[len(techAsset.Communication_links[title].Data_assets_received)-1] = ""     // Erase last element (write zero value).
									x := techAsset.Communication_links[title]
									x.Data_assets_received = techAsset.Communication_links[title].Data_assets_received[:len(techAsset.Communication_links[title].Data_assets_received)-1] // Truncate slice.
									techAsset.Communication_links[title] = x
								}
							}
						}
					}
				}
				for indivRiskCatTitle, indivRiskCat := range modelInput.Individual_risk_categories {
					if indivRiskCat.Risks_identified != nil {
						for indivRiskInstanceTitle, indivRiskInstance := range indivRiskCat.Risks_identified {
							if indivRiskInstance.Most_relevant_data_asset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle]
								x.Most_relevant_data_asset = "" // TODO needs more testing
								modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.Data_assets, title)
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
		for title, sharedRuntime := range modelInput.Shared_runtimes {
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
				delete(modelInput.Shared_runtimes, title)
				modelInput.Shared_runtimes[payload.Title] = sharedRuntimeInput
				idChanged := sharedRuntimeInput.ID != sharedRuntime.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					for indivRiskCatTitle, indivRiskCat := range modelInput.Individual_risk_categories {
						if indivRiskCat.Risks_identified != nil {
							for indivRiskInstanceTitle, indivRiskInstance := range indivRiskCat.Risks_identified {
								if indivRiskInstance.Most_relevant_shared_runtime == sharedRuntime.ID { // apply the ID change
									x := modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle]
									x.Most_relevant_shared_runtime = sharedRuntimeInput.ID // TODO needs more testing
									modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle] = x
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
		for title, dataAsset := range modelInput.Data_assets {
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
				delete(modelInput.Data_assets, title)
				modelInput.Data_assets[payload.Title] = dataAssetInput
				idChanged := dataAssetInput.ID != dataAsset.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					// also update all usages to point to the new (changed) ID !!
					for techAssetTitle, techAsset := range modelInput.Technical_assets {
						if techAsset.Data_assets_processed != nil {
							for i, parsedChangeCandidateAsset := range techAsset.Data_assets_processed {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.Technical_assets[techAssetTitle].Data_assets_processed[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.Data_assets_stored != nil {
							for i, parsedChangeCandidateAsset := range techAsset.Data_assets_stored {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.Technical_assets[techAssetTitle].Data_assets_stored[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.Communication_links != nil {
							for title, commLink := range techAsset.Communication_links {
								for i, dataAssetSent := range commLink.Data_assets_sent {
									referencedAsset := fmt.Sprintf("%v", dataAssetSent)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.Technical_assets[techAssetTitle].Communication_links[title].Data_assets_sent[i] = dataAssetInput.ID
									}
								}
								for i, dataAssetReceived := range commLink.Data_assets_received {
									referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.Technical_assets[techAssetTitle].Communication_links[title].Data_assets_received[i] = dataAssetInput.ID
									}
								}
							}
						}
					}
					for indivRiskCatTitle, indivRiskCat := range modelInput.Individual_risk_categories {
						if indivRiskCat.Risks_identified != nil {
							for indivRiskInstanceTitle, indivRiskInstance := range indivRiskCat.Risks_identified {
								if indivRiskInstance.Most_relevant_data_asset == dataAsset.ID { // apply the ID change
									x := modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle]
									x.Most_relevant_data_asset = dataAssetInput.ID // TODO needs more testing
									modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle] = x
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
		for title, sharedRuntime := range modelInput.Shared_runtimes {
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
		if _, exists := modelInput.Shared_runtimes[payload.Title]; exists {
			context.JSON(http.StatusConflict, gin.H{
				"error": "shared runtime with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by it's "id", so do this uniqueness check also
		for _, runtime := range modelInput.Shared_runtimes {
			if runtime.ID == payload.Id {
				context.JSON(http.StatusConflict, gin.H{
					"error": "shared runtime with this id already exists",
				})
				return
			}
		}
		if !checkTechnicalAssetsExisting(modelInput, payload.Technical_assets_running) {
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "referenced technical asset does not exist",
			})
			return
		}
		sharedRuntimeInput, ok := populateSharedRuntime(context, payload)
		if !ok {
			return
		}
		if modelInput.Shared_runtimes == nil {
			modelInput.Shared_runtimes = make(map[string]model.InputSharedRuntime)
		}
		modelInput.Shared_runtimes[payload.Title] = sharedRuntimeInput
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
		for _, val := range modelInput.Technical_assets {
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

func populateSharedRuntime(context *gin.Context, payload payloadSharedRuntime) (sharedRuntimeInput model.InputSharedRuntime, ok bool) {
	sharedRuntimeInput = model.InputSharedRuntime{
		ID:                       payload.Id,
		Description:              payload.Description,
		Tags:                     lowerCaseAndTrim(payload.Tags),
		Technical_assets_running: payload.Technical_assets_running,
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
		for title, sharedRuntime := range modelInput.Shared_runtimes {
			if sharedRuntime.ID == context.Param("shared-runtime-id") {
				// also remove all usages of this shared runtime !!
				for indivRiskCatTitle, indivRiskCat := range modelInput.Individual_risk_categories {
					if indivRiskCat.Risks_identified != nil {
						for indivRiskInstanceTitle, indivRiskInstance := range indivRiskCat.Risks_identified {
							if indivRiskInstance.Most_relevant_shared_runtime == sharedRuntime.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle]
								x.Most_relevant_shared_runtime = "" // TODO needs more testing
								modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.Shared_runtimes, title)
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
		if _, exists := modelInput.Data_assets[payload.Title]; exists {
			context.JSON(http.StatusConflict, gin.H{
				"error": "data asset with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by it's "id", so do this uniqueness check also
		for _, asset := range modelInput.Data_assets {
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
		if modelInput.Data_assets == nil {
			modelInput.Data_assets = make(map[string]model.InputDataAsset)
		}
		modelInput.Data_assets[payload.Title] = dataAssetInput
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
		ID:                       payload.Id,
		Description:              payload.Description,
		Usage:                    usage.String(),
		Tags:                     lowerCaseAndTrim(payload.Tags),
		Origin:                   payload.Origin,
		Owner:                    payload.Owner,
		Quantity:                 quantity.String(),
		Confidentiality:          confidentiality.String(),
		Integrity:                integrity.String(),
		Availability:             availability.String(),
		Justification_cia_rating: payload.Justification_cia_rating,
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
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Data_assets)
	}
}

func getTrustBoundaries(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Trust_boundaries)
	}
}

func getSharedRuntimes(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Shared_runtimes)
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
		tmpResultFile, err := ioutil.TempFile(model.TempFolder, "threagile-*.yaml")
		checkErr(err)
		err = ioutil.WriteFile(tmpResultFile.Name(), []byte(yamlText), 0400)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to stream model file",
			})
			return
		}
		defer os.Remove(tmpResultFile.Name())
		context.FileAttachment(tmpResultFile.Name(), "threagile.yaml")
	}
}

type payloadModels struct {
	ID                 string    `json:"id"`
	Title              string    `json:"title"`
	Timestamp_created  time.Time `json:"timestamp_created"`
	Timestamp_modified time.Time `json:"timestamp_modified"`
}

type payloadCover struct {
	Title  string       `json:"title"`
	Date   time.Time    `json:"date"`
	Author model.Author `json:"author"`
}

type payloadOverview struct {
	Management_summary_comment string         `json:"management_summary_comment"`
	Business_criticality       string         `json:"business_criticality"`
	Business_overview          model.Overview `json:"business_overview"`
	Technical_overview         model.Overview `json:"technical_overview"`
}

type payloadAbuseCases map[string]string

type payloadSecurityRequirements map[string]string

type payloadDataAsset struct {
	Title                    string   `json:"title"`
	Id                       string   `json:"id"`
	Description              string   `json:"description"`
	Usage                    string   `json:"usage"`
	Tags                     []string `json:"tags"`
	Origin                   string   `json:"origin"`
	Owner                    string   `json:"owner"`
	Quantity                 string   `json:"quantity"`
	Confidentiality          string   `json:"confidentiality"`
	Integrity                string   `json:"integrity"`
	Availability             string   `json:"availability"`
	Justification_cia_rating string   `json:"justification_cia_rating"`
}

type payloadSharedRuntime struct {
	Title                    string   `json:"title"`
	Id                       string   `json:"id"`
	Description              string   `json:"description"`
	Tags                     []string `json:"tags"`
	Technical_assets_running []string `json:"technical_assets_running"`
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
		modelInput.Security_requirements = payload
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
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Security_requirements)
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
		modelInput.Abuse_cases = payload
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
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Abuse_cases)
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
		criticality, err := model.ParseCriticality(payload.Business_criticality)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		modelInput.Management_summary_comment = payload.Management_summary_comment
		modelInput.Business_criticality = criticality.String()
		modelInput.Business_overview.Description = payload.Business_overview.Description
		modelInput.Business_overview.Images = payload.Business_overview.Images
		modelInput.Technical_overview.Description = payload.Technical_overview.Description
		modelInput.Technical_overview.Images = payload.Technical_overview.Images
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
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, gin.H{
			"management_summary_comment": model.Management_summary_comment,
			"business_criticality":       model.Business_criticality,
			"business_overview":          model.Business_overview,
			"technical_overview":         model.Technical_overview,
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
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, gin.H{
			"title":  model.Title,
			"date":   model.Date,
			"author": model.Author,
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

	uuid := uuid.New().String()
	err := os.Mkdir(folderNameForModel(folderNameOfKey, uuid), 0700)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create model",
		})
		return
	}

	yaml := `title: New Threat Model
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

	ok = writeModelYAML(context, yaml, key, folderNameForModel(folderNameOfKey, uuid), "New Model Creation", true)
	if ok {
		context.JSON(http.StatusCreated, gin.H{
			"message": "model created",
			"id":      uuid,
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
	modelFolders, err := ioutil.ReadDir(folderNameOfKey)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	for _, fileInfo := range modelFolders {
		if fileInfo.IsDir() {
			modelStat, err := os.Stat(folderNameOfKey + "/" + fileInfo.Name() + "/threagile.yaml")
			if err != nil {
				log.Println(err)
				context.JSON(http.StatusNotFound, gin.H{
					"error": "unable to list model",
				})
				return
			}
			model, _, ok := readModel(context, fileInfo.Name(), key, folderNameOfKey)
			if !ok {
				return
			}
			result = append(result, payloadModels{
				ID:                 fileInfo.Name(),
				Title:              model.Title,
				Timestamp_created:  fileInfo.ModTime(),
				Timestamp_modified: modelStat.ModTime(),
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
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	fileBytes, err := ioutil.ReadFile(modelFolder + "/threagile.yaml")
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	nonce := fileBytes[0:12]
	ciphertext := fileBytes[12:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
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
	buf.ReadFrom(r)
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
		modelInput.Threagile_version = model.ThreagileVersion
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
	w.Write([]byte(yaml))
	w.Close()
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
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
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
	f.Write(nonce)
	f.Write(ciphertext)
	f.Close()
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
	input, err := ioutil.ReadFile(modelFolder + "/threagile.yaml")
	if err != nil {
		return err
	}
	historyFile := historyFolder + "/" + time.Now().Format("2006-01-02 15:04:05") + " " + changeReasonForHistory + ".backup"
	err = ioutil.WriteFile(historyFile, input, 0400)
	if err != nil {
		return err
	}
	// now delete any old files if over limit to keep
	files, err := ioutil.ReadDir(historyFolder)
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
	for keyCheck, _ := range createdObjectsThrottler {
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
		timeoutStruct.lastAcessedNanotime = time.Now().UnixNano()
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
	print3rdParty := flag.Bool("print-3rd-party-licenses", false, "print 3rd-party license information")
	license := flag.Bool("print-license", false, "print license information")
	flag.Usage = func() {
		printLogo()
		fmt.Fprintf(os.Stderr, "Usage: threagile [options]")
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
		fmt.Println(add_build_pipeline.GetMacroDetails().ID, "-->", add_build_pipeline.GetMacroDetails().Title)
		fmt.Println(add_vault.GetMacroDetails().ID, "-->", add_vault.GetMacroDetails().Title)
		fmt.Println(pretty_print.GetMacroDetails().ID, "-->", pretty_print.GetMacroDetails().Title)
		fmt.Println(remove_unused_tags.GetMacroDetails().ID, "-->", remove_unused_tags.GetMacroDetails().Title)
		fmt.Println(seed_risk_tracking.GetMacroDetails().ID, "-->", seed_risk_tracking.GetMacroDetails().Title)
		fmt.Println(seed_tags.GetMacroDetails().ID, "-->", seed_tags.GetMacroDetails().Title)
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
		for id, customRule := range customRiskRules {
			fmt.Println(id, "-->", customRule.Category().Title, "--> with tags:", customRule.SupportedTags())
		}
		fmt.Println()
		fmt.Println("--------------------")
		fmt.Println("Built-in risk rules:")
		fmt.Println("--------------------")
		fmt.Println(accidental_secret_leak.Category().Id, "-->", accidental_secret_leak.Category().Title, "--> with tags:", accidental_secret_leak.SupportedTags())
		fmt.Println(code_backdooring.Category().Id, "-->", code_backdooring.Category().Title, "--> with tags:", code_backdooring.SupportedTags())
		fmt.Println(container_baseimage_backdooring.Category().Id, "-->", container_baseimage_backdooring.Category().Title, "--> with tags:", container_baseimage_backdooring.SupportedTags())
		fmt.Println(container_platform_escape.Category().Id, "-->", container_platform_escape.Category().Title, "--> with tags:", container_platform_escape.SupportedTags())
		fmt.Println(cross_site_request_forgery.Category().Id, "-->", cross_site_request_forgery.Category().Title, "--> with tags:", cross_site_request_forgery.SupportedTags())
		fmt.Println(cross_site_scripting.Category().Id, "-->", cross_site_scripting.Category().Title, "--> with tags:", cross_site_scripting.SupportedTags())
		fmt.Println(dos_risky_access_across_trust_boundary.Category().Id, "-->", dos_risky_access_across_trust_boundary.Category().Title, "--> with tags:", dos_risky_access_across_trust_boundary.SupportedTags())
		fmt.Println(incomplete_model.Category().Id, "-->", incomplete_model.Category().Title, "--> with tags:", incomplete_model.SupportedTags())
		fmt.Println(ldap_injection.Category().Id, "-->", ldap_injection.Category().Title, "--> with tags:", ldap_injection.SupportedTags())
		fmt.Println(missing_authentication.Category().Id, "-->", missing_authentication.Category().Title, "--> with tags:", missing_authentication.SupportedTags())
		fmt.Println(missing_authentication_second_factor.Category().Id, "-->", missing_authentication_second_factor.Category().Title, "--> with tags:", missing_authentication_second_factor.SupportedTags())
		fmt.Println(missing_build_infrastructure.Category().Id, "-->", missing_build_infrastructure.Category().Title, "--> with tags:", missing_build_infrastructure.SupportedTags())
		fmt.Println(missing_cloud_hardening.Category().Id, "-->", missing_cloud_hardening.Category().Title, "--> with tags:", missing_cloud_hardening.SupportedTags())
		fmt.Println(missing_file_validation.Category().Id, "-->", missing_file_validation.Category().Title, "--> with tags:", missing_file_validation.SupportedTags())
		fmt.Println(missing_hardening.Category().Id, "-->", missing_hardening.Category().Title, "--> with tags:", missing_hardening.SupportedTags())
		fmt.Println(missing_identity_propagation.Category().Id, "-->", missing_identity_propagation.Category().Title, "--> with tags:", missing_identity_propagation.SupportedTags())
		fmt.Println(missing_identity_provider_isolation.Category().Id, "-->", missing_identity_provider_isolation.Category().Title, "--> with tags:", missing_identity_provider_isolation.SupportedTags())
		fmt.Println(missing_identity_store.Category().Id, "-->", missing_identity_store.Category().Title, "--> with tags:", missing_identity_store.SupportedTags())
		fmt.Println(missing_network_segmentation.Category().Id, "-->", missing_network_segmentation.Category().Title, "--> with tags:", missing_network_segmentation.SupportedTags())
		fmt.Println(missing_vault.Category().Id, "-->", missing_vault.Category().Title, "--> with tags:", missing_vault.SupportedTags())
		fmt.Println(missing_vault_isolation.Category().Id, "-->", missing_vault_isolation.Category().Title, "--> with tags:", missing_vault_isolation.SupportedTags())
		fmt.Println(missing_waf.Category().Id, "-->", missing_waf.Category().Title, "--> with tags:", missing_waf.SupportedTags())
		fmt.Println(mixed_targets_on_shared_runtime.Category().Id, "-->", mixed_targets_on_shared_runtime.Category().Title, "--> with tags:", mixed_targets_on_shared_runtime.SupportedTags())
		fmt.Println(path_traversal.Category().Id, "-->", path_traversal.Category().Title, "--> with tags:", path_traversal.SupportedTags())
		fmt.Println(push_instead_of_pull_deployment.Category().Id, "-->", push_instead_of_pull_deployment.Category().Title, "--> with tags:", push_instead_of_pull_deployment.SupportedTags())
		fmt.Println(search_query_injection.Category().Id, "-->", search_query_injection.Category().Title, "--> with tags:", search_query_injection.SupportedTags())
		fmt.Println(server_side_request_forgery.Category().Id, "-->", server_side_request_forgery.Category().Title, "--> with tags:", server_side_request_forgery.SupportedTags())
		fmt.Println(service_registry_poisoning.Category().Id, "-->", service_registry_poisoning.Category().Title, "--> with tags:", service_registry_poisoning.SupportedTags())
		fmt.Println(sql_nosql_injection.Category().Id, "-->", sql_nosql_injection.Category().Title, "--> with tags:", sql_nosql_injection.SupportedTags())
		fmt.Println(unchecked_deployment.Category().Id, "-->", unchecked_deployment.Category().Title, "--> with tags:", unchecked_deployment.SupportedTags())
		fmt.Println(unencrypted_asset.Category().Id, "-->", unencrypted_asset.Category().Title, "--> with tags:", unencrypted_asset.SupportedTags())
		fmt.Println(unencrypted_communication.Category().Id, "-->", unencrypted_communication.Category().Title, "--> with tags:", unencrypted_communication.SupportedTags())
		fmt.Println(unguarded_access_from_internet.Category().Id, "-->", unguarded_access_from_internet.Category().Title, "--> with tags:", unguarded_access_from_internet.SupportedTags())
		fmt.Println(unguarded_direct_datastore_access.Category().Id, "-->", unguarded_direct_datastore_access.Category().Title, "--> with tags:", unguarded_direct_datastore_access.SupportedTags())
		fmt.Println(unnecessary_communication_link.Category().Id, "-->", unnecessary_communication_link.Category().Title, "--> with tags:", unnecessary_communication_link.SupportedTags())
		fmt.Println(unnecessary_data_asset.Category().Id, "-->", unnecessary_data_asset.Category().Title, "--> with tags:", unnecessary_data_asset.SupportedTags())
		fmt.Println(unnecessary_data_transfer.Category().Id, "-->", unnecessary_data_transfer.Category().Title, "--> with tags:", unnecessary_data_transfer.SupportedTags())
		fmt.Println(unnecessary_technical_asset.Category().Id, "-->", unnecessary_technical_asset.Category().Title, "--> with tags:", unnecessary_technical_asset.SupportedTags())
		fmt.Println(untrusted_deserialization.Category().Id, "-->", untrusted_deserialization.Category().Title, "--> with tags:", untrusted_deserialization.SupportedTags())
		fmt.Println(wrong_communication_link_content.Category().Id, "-->", wrong_communication_link_content.Category().Title, "--> with tags:", wrong_communication_link_content.SupportedTags())
		fmt.Println(wrong_trust_boundary_content.Category().Id, "-->", wrong_trust_boundary_content.Category().Title, "--> with tags:", wrong_trust_boundary_content.SupportedTags())
		fmt.Println(xml_external_entity.Category().Id, "-->", xml_external_entity.Category().Title, "--> with tags:", xml_external_entity.SupportedTags())
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
		content, err := ioutil.ReadFile("/app/LICENSE.txt")
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
	copyFile("/app/threagile-example-model.yaml", *outputDir+"/threagile-example-model.yaml")
}

func createStubModelFile() {
	loadCustomRiskRules()
	stub, err := ioutil.ReadFile("/app/threagile-stub-model.yaml")
	checkErr(err)
	err = ioutil.WriteFile(*outputDir+"/threagile-stub-model.yaml", addSupportedTags(stub), 0644)
	checkErr(err)
}

func createEditingSupportFiles() {
	copyFile("/app/schema.json", *outputDir+"/schema.json")
	copyFile("/app/live-templates.txt", *outputDir+"/live-templates.txt")
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
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func parseModel(inputFilename string) {
	if *verbose {
		fmt.Println("Parsing model:", inputFilename)
	}
	modelYaml, err := ioutil.ReadFile(inputFilename)
	if err == nil {
		modelInput = model.ModelInput{}
		err = yaml.Unmarshal(modelYaml, &modelInput)
		checkErr(err)
		//fmt.Println(modelInput)

		var businessCriticality model.Criticality
		switch modelInput.Business_criticality {
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
			panic(errors.New("unknown 'business_criticality' value of application: " + modelInput.Business_criticality))
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
			ManagementSummaryComment:       modelInput.Management_summary_comment,
			BusinessCriticality:            businessCriticality,
			BusinessOverview:               removePathElementsFromImageFiles(modelInput.Business_overview),
			TechnicalOverview:              removePathElementsFromImageFiles(modelInput.Technical_overview),
			Questions:                      modelInput.Questions,
			AbuseCases:                     modelInput.Abuse_cases,
			SecurityRequirements:           modelInput.Security_requirements,
			TagsAvailable:                  lowerCaseAndTrim(modelInput.Tags_available),
			DiagramTweakNodesep:            modelInput.Diagram_tweak_nodesep,
			DiagramTweakRanksep:            modelInput.Diagram_tweak_ranksep,
			DiagramTweakEdgeLayout:         modelInput.Diagram_tweak_edge_layout,
			DiagramTweakSuppressEdgeLabels: modelInput.Diagram_tweak_suppress_edge_labels,
			DiagramTweakLayoutLeftToRight:  modelInput.Diagram_tweak_layout_left_to_right,
			DiagramTweakInvisibleConnectionsBetweenAssets: modelInput.Diagram_tweak_invisible_connections_between_assets,
			DiagramTweakSameRankAssets:                    modelInput.Diagram_tweak_same_rank_assets,
		}
		if model.ParsedModelRoot.DiagramTweakNodesep == 0 {
			model.ParsedModelRoot.DiagramTweakNodesep = 2
		}
		if model.ParsedModelRoot.DiagramTweakRanksep == 0 {
			model.ParsedModelRoot.DiagramTweakRanksep = 2
		}

		// Data Assets ===============================================================================
		model.ParsedModelRoot.DataAssets = make(map[string]model.DataAsset)
		for title, asset := range modelInput.Data_assets {
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
				JustificationCiaRating: fmt.Sprintf("%v", asset.Justification_cia_rating),
			}
		}

		// Technical Assets ===============================================================================
		model.ParsedModelRoot.TechnicalAssets = make(map[string]model.TechnicalAsset)
		for title, asset := range modelInput.Technical_assets {
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
			if asset.Data_assets_processed != nil {
				dataAssetsProcessed = make([]string, len(asset.Data_assets_processed))
				for i, parsedProcessedAsset := range asset.Data_assets_processed {
					referencedAsset := fmt.Sprintf("%v", parsedProcessedAsset)
					checkDataAssetTargetExists(referencedAsset, "technical asset '"+title+"'")
					dataAssetsProcessed[i] = referencedAsset
				}
			}

			var dataAssetsStored = make([]string, 0)
			if asset.Data_assets_stored != nil {
				dataAssetsStored = make([]string, len(asset.Data_assets_stored))
				for i, parsedStoredAssets := range asset.Data_assets_stored {
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
			case model.DataWithEnduserIndividualKey.String():
				encryption = model.DataWithEnduserIndividualKey
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
			if asset.Data_formats_accepted != nil {
				for _, dataFormatName := range asset.Data_formats_accepted {
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
			if asset.Communication_links != nil {
				for commLinkTitle, commLink := range asset.Communication_links {
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
					case model.EnduserIdentityPropagation.String():
						authorization = model.EnduserIdentityPropagation
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
					case model.JDBC_encrypted.String():
						protocol = model.JDBC_encrypted
					case model.ODBC.String():
						protocol = model.ODBC
					case model.ODBC_encrypted.String():
						protocol = model.ODBC_encrypted
					case model.SQL_access_protocol.String():
						protocol = model.SQL_access_protocol
					case model.SQL_access_protocol_encrypted.String():
						protocol = model.SQL_access_protocol_encrypted
					case model.NoSQL_access_protocol.String():
						protocol = model.NoSQL_access_protocol
					case model.NoSQL_access_protocol_encrypted.String():
						protocol = model.NoSQL_access_protocol_encrypted
					case model.TEXT.String():
						protocol = model.TEXT
					case model.TEXT_encrypted.String():
						protocol = model.TEXT_encrypted
					case model.BINARY.String():
						protocol = model.BINARY
					case model.BINARY_encrypted.String():
						protocol = model.BINARY_encrypted
					case model.SSH.String():
						protocol = model.SSH
					case model.SSH_tunnel.String():
						protocol = model.SSH_tunnel
					case model.SMTP.String():
						protocol = model.SMTP
					case model.SMTP_encrypted.String():
						protocol = model.SMTP_encrypted
					case model.POP3.String():
						protocol = model.POP3
					case model.POP3_encrypted.String():
						protocol = model.POP3_encrypted
					case model.IMAP.String():
						protocol = model.IMAP
					case model.IMAP_encrypted.String():
						protocol = model.IMAP_encrypted
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
					case model.SMB_encrypted.String():
						protocol = model.SMB_encrypted
					case model.LocalFileAccess.String():
						protocol = model.LocalFileAccess
					case model.NRPE.String():
						protocol = model.NRPE
					case model.XMPP.String():
						protocol = model.XMPP
					case model.IIOP.String():
						protocol = model.IIOP
					case model.IIOP_encrypted.String():
						protocol = model.IIOP_encrypted
					case model.JRMP.String():
						protocol = model.JRMP
					case model.JRMP_encrypted.String():
						protocol = model.JRMP_encrypted
					case model.InProcessLibraryCall.String():
						protocol = model.InProcessLibraryCall
					case model.ContainerSpawning.String():
						protocol = model.ContainerSpawning
					default:
						panic(errors.New("unknown 'protocol' of technical asset '" + title + "' communication link '" + commLinkTitle + "': " + fmt.Sprintf("%v", commLink.Protocol)))
					}

					if commLink.Data_assets_sent != nil {
						for _, dataAssetSent := range commLink.Data_assets_sent {
							referencedAsset := fmt.Sprintf("%v", dataAssetSent)
							checkDataAssetTargetExists(referencedAsset, "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
							dataAssetsSent = append(dataAssetsSent, referencedAsset)
						}
					}

					if commLink.Data_assets_received != nil {
						for _, dataAssetReceived := range commLink.Data_assets_received {
							referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
							checkDataAssetTargetExists(referencedAsset, "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
							dataAssetsReceived = append(dataAssetsReceived, referencedAsset)
						}
					}

					if commLink.Diagram_tweak_weight > 0 {
						weight = commLink.Diagram_tweak_weight
					}

					constraint = !commLink.Diagram_tweak_constraint

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
						IpFiltered:             commLink.IP_filtered,
						Readonly:               commLink.Readonly,
						DataAssetsSent:         dataAssetsSent,
						DataAssetsReceived:     dataAssetsReceived,
						DiagramTweakWeight:     weight,
						DiagramTweakConstraint: constraint,
					}
					communicationLinks = append(communicationLinks, commLink)
					// track all comm links
					model.CommunicationLinks[commLink.Id] = commLink
					// keep track of map of *all* comm links mapped by target-id (to be able to lookup "who is calling me" kind of things)
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
				MultiTenant:             asset.Multi_tenant,
				Redundant:               asset.Redundant,
				CustomDevelopedParts:    asset.Custom_developed_parts,
				UsedAsClientByHuman:     asset.Used_as_client_by_human,
				OutOfScope:              asset.Out_of_scope,
				JustificationOutOfScope: fmt.Sprintf("%v", asset.Justification_out_of_scope),
				Owner:                   fmt.Sprintf("%v", asset.Owner),
				Confidentiality:         confidentiality,
				Integrity:               integrity,
				Availability:            availability,
				JustificationCiaRating:  fmt.Sprintf("%v", asset.Justification_cia_rating),
				DataAssetsProcessed:     dataAssetsProcessed,
				DataAssetsStored:        dataAssetsStored,
				DataFormatsAccepted:     dataFormatsAccepted,
				CommunicationLinks:      communicationLinks,
				DiagramTweakOrder:       asset.Diagram_tweak_order,
			}
		}

		// Trust Boundaries ===============================================================================
		checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries := make(map[string]bool)
		model.ParsedModelRoot.TrustBoundaries = make(map[string]model.TrustBoundary)
		for title, boundary := range modelInput.Trust_boundaries {
			id := fmt.Sprintf("%v", boundary.ID)

			var technicalAssetsInside = make([]string, 0)
			if boundary.Technical_assets_inside != nil {
				parsedInsideAssets := boundary.Technical_assets_inside
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
			if boundary.Trust_boundaries_nested != nil {
				parsedNestedBoundaries := boundary.Trust_boundaries_nested
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
		for title, runtime := range modelInput.Shared_runtimes {
			id := fmt.Sprintf("%v", runtime.ID)

			var technicalAssetsRunning = make([]string, 0)
			if runtime.Technical_assets_running != nil {
				parsedRunningAssets := runtime.Technical_assets_running
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
				Tags:                   checkTags((runtime.Tags), "shared runtime '"+title+"'"),
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
		for title, indivCat := range modelInput.Individual_risk_categories {
			id := fmt.Sprintf("%v", indivCat.ID)

			var function model.RiskFunction
			switch indivCat.Function {
			case model.BusinessSide.String():
				function = model.BusinessSide
			case model.Architecture.String():
				function = model.Architecture
			case model.Development.String():
				function = model.Development
			case model.Operations.String():
				function = model.Operations
			default:
				panic(errors.New("unknown 'function' value of individual risk category '" + title + "': " + fmt.Sprintf("%v", indivCat.Function)))
			}

			var stride model.STRIDE
			switch indivCat.STRIDE {
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
				panic(errors.New("unknown 'stride' value of individual risk category '" + title + "': " + fmt.Sprintf("%v", indivCat.STRIDE)))
			}

			cat := model.RiskCategory{
				Id:                         id,
				Title:                      title,
				Description:                withDefault(fmt.Sprintf("%v", indivCat.Description), title),
				Impact:                     fmt.Sprintf("%v", indivCat.Impact),
				ASVS:                       fmt.Sprintf("%v", indivCat.ASVS),
				CheatSheet:                 fmt.Sprintf("%v", indivCat.Cheat_sheet),
				Action:                     fmt.Sprintf("%v", indivCat.Action),
				Mitigation:                 fmt.Sprintf("%v", indivCat.Mitigation),
				Check:                      fmt.Sprintf("%v", indivCat.Check),
				DetectionLogic:             fmt.Sprintf("%v", indivCat.Detection_logic),
				RiskAssessment:             fmt.Sprintf("%v", indivCat.Risk_assessment),
				FalsePositives:             fmt.Sprintf("%v", indivCat.False_positives),
				Function:                   function,
				STRIDE:                     stride,
				ModelFailurePossibleReason: indivCat.Model_failure_possible_reason,
				CWE:                        indivCat.CWE,
			}
			checkIdSyntax(id)
			if _, exists := model.ParsedModelRoot.IndividualRiskCategories[id]; exists {
				panic(errors.New("duplicate id used: " + id))
			}
			model.ParsedModelRoot.IndividualRiskCategories[id] = cat

			// NOW THE INDIVIDUAL RISK INSTANCES:
			//individualRiskInstances := make([]model.Risk, 0)
			if indivCat.Risks_identified != nil { // TODO: also add syntax checks of input YAML when linked asset is not found or when syntehtic-id is already used...
				for title, indivRiskInstance := range indivCat.Risks_identified {
					var severity model.RiskSeverity
					var exploitationLikelihood model.RiskExploitationLikelihood
					var exploitationImpact model.RiskExploitationImpact
					var mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string
					var dataBreachProbability model.DataBreachProbability
					var dataBreachTechnicalAssetIDs []string

					switch indivRiskInstance.Severity {
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
						panic(errors.New("unknown 'severity' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", indivRiskInstance.Severity)))
					}

					switch indivRiskInstance.Exploitation_likelihood {
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
						panic(errors.New("unknown 'exploitation_likelihood' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", indivRiskInstance.Exploitation_likelihood)))
					}

					switch indivRiskInstance.Exploitation_impact {
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
						panic(errors.New("unknown 'exploitation_impact' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", indivRiskInstance.Exploitation_impact)))
					}

					if len(indivRiskInstance.Most_relevant_data_asset) > 0 {
						mostRelevantDataAssetId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_data_asset)
						checkDataAssetTargetExists(mostRelevantDataAssetId, "individual risk '"+title+"'")
					}

					if len(indivRiskInstance.Most_relevant_technical_asset) > 0 {
						mostRelevantTechnicalAssetId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_technical_asset)
						checkTechnicalAssetExists(mostRelevantTechnicalAssetId, "individual risk '"+title+"'", false)
					}

					if len(indivRiskInstance.Most_relevant_communication_link) > 0 {
						mostRelevantCommunicationLinkId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_communication_link)
						checkCommunicationLinkExists(mostRelevantCommunicationLinkId, "individual risk '"+title+"'")
					}

					if len(indivRiskInstance.Most_relevant_trust_boundary) > 0 {
						mostRelevantTrustBoundaryId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_trust_boundary)
						checkTrustBoundaryExists(mostRelevantTrustBoundaryId, "individual risk '"+title+"'")
					}

					if len(indivRiskInstance.Most_relevant_shared_runtime) > 0 {
						mostRelevantSharedRuntimeId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_shared_runtime)
						checkSharedRuntimeExists(mostRelevantSharedRuntimeId, "individual risk '"+title+"'")
					}

					switch indivRiskInstance.Data_breach_probability {
					case model.Improbable.String():
						dataBreachProbability = model.Improbable
					case model.Possible.String():
						dataBreachProbability = model.Possible
					case model.Probable.String():
						dataBreachProbability = model.Probable
					case "": // added default
						dataBreachProbability = model.Possible
					default:
						panic(errors.New("unknown 'data_breach_probability' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", indivRiskInstance.Data_breach_probability)))
					}

					if indivRiskInstance.Data_breach_technical_assets != nil {
						dataBreachTechnicalAssetIDs = make([]string, len(indivRiskInstance.Data_breach_technical_assets))
						for i, parsedReferencedAsset := range indivRiskInstance.Data_breach_technical_assets {
							assetId := fmt.Sprintf("%v", parsedReferencedAsset)
							checkTechnicalAssetExists(assetId, "data breach technical assets of individual risk '"+title+"'", false)
							dataBreachTechnicalAssetIDs[i] = assetId
						}
					}

					checkErr(err)

					indivRiskInstance := model.Risk{
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
					model.GeneratedRisksByCategory[cat] = append(model.GeneratedRisksByCategory[cat], indivRiskInstance)
				}
			}
		}

		// Risk Tracking ===============================================================================
		model.ParsedModelRoot.RiskTracking = make(map[string]model.RiskTracking)
		for syntheticRiskId, riskTracking := range modelInput.Risk_tracking {
			justification := fmt.Sprintf("%v", riskTracking.Justification)
			checkedBy := fmt.Sprintf("%v", riskTracking.Checked_by)
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
	for i, _ := range overview.Images {
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
		for syntheticRiskId, _ := range model.GeneratedRisksBySyntheticId {
			if matchingRiskIdExpression.Match([]byte(syntheticRiskId)) && hasNotYetAnyDirectNonWildcardRiskTrackings(syntheticRiskId) {
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

func hasNotYetAnyDirectNonWildcardRiskTrackings(syntheticRiskId string) bool {
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
	h.Write([]byte(s))
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
	defer file.Close()
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
	for k, _ := range model.ParsedModelRoot.TrustBoundaries {
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
			penwidth := 4.5
			if len(trustBoundary.TrustBoundariesNested) > 0 {
				//color, fontColor, style, fontname = colors.Blue, colors.Blue, "dashed", "Verdana"
				penwidth = 5.5
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
      penwidth="` + fmt.Sprintf("%f", penwidth) + `"
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
	for i, _ := range subgraphSnippetsById {
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
	for k, _ := range subgraphSnippetsById {
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
	techAssets := []model.TechnicalAsset{}
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
				if !suppressBidirectionalArrows { // as it does not work as bug in grahviz with ortho: https://gitlab.com/graphviz/graphviz/issues/144
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
	defer file.Close()
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
	tmpFileDOT, err := ioutil.TempFile(model.TempFolder, "diagram-*-.gv")
	checkErr(err)
	defer os.Remove(tmpFileDOT.Name())

	tmpFilePNG, err := ioutil.TempFile(model.TempFolder, "diagram-*-.png")
	checkErr(err)
	defer os.Remove(tmpFilePNG.Name())

	// copy into tmp file as input
	input, err := ioutil.ReadFile(dotFile.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = ioutil.WriteFile(tmpFileDOT.Name(), input, 0644)
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
	input, err = ioutil.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = ioutil.WriteFile(targetDir+"/"+dataFlowDiagramFilenamePNG, input, 0644)
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
	tmpFileDOT, err := ioutil.TempFile(model.TempFolder, "diagram-*-.gv")
	checkErr(err)
	defer os.Remove(tmpFileDOT.Name())

	tmpFilePNG, err := ioutil.TempFile(model.TempFolder, "diagram-*-.png")
	checkErr(err)
	defer os.Remove(tmpFilePNG.Name())

	// copy into tmp file as input
	input, err := ioutil.ReadFile(dotFile.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = ioutil.WriteFile(tmpFileDOT.Name(), input, 0644)
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
	input, err = ioutil.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = ioutil.WriteFile(targetDir+"/"+dataAssetDiagramFilenamePNG, input, 0644)
	if err != nil {
		fmt.Println("Error creating", dataAssetDiagramFilenamePNG)
		fmt.Println(err)
		return
	}
}
