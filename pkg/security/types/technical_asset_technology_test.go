/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseTechnicalAssetTechnologyTest struct {
	input         string
	expected      TechnicalAssetTechnology
	expectedError error
}

func TestParseTechnicalAssetTechnology(t *testing.T) {
	testCases := map[string]ParseTechnicalAssetTechnologyTest{
		"unknown-technology": {
			input:    "unknown-technology",
			expected: UnknownTechnology,
		},
		"client-system": {
			input:    "client-system",
			expected: ClientSystem,
		},
		"browser": {
			input:    "browser",
			expected: Browser,
		},
		"desktop": {
			input:    "desktop",
			expected: Desktop,
		},
		"mobile-app": {
			input:    "mobile-app",
			expected: MobileApp,
		},
		"devops-client": {
			input:    "devops-client",
			expected: DevOpsClient,
		},
		"web-server": {
			input:    "web-server",
			expected: WebServer,
		},
		"web-application": {
			input:    "web-application",
			expected: WebApplication,
		},
		"application-server": {
			input:    "application-server",
			expected: ApplicationServer,
		},
		"database": {
			input:    "database",
			expected: Database,
		},
		"file-server": {
			input:    "file-server",
			expected: FileServer,
		},
		"local-file-system": {
			input:    "local-file-system",
			expected: LocalFileSystem,
		},
		"erp": {
			input:    "erp",
			expected: ERP,
		},
		"cms": {
			input:    "cms",
			expected: CMS,
		},
		"web-service-rest": {
			input:    "web-service-rest",
			expected: WebServiceREST,
		},
		"web-service-soap": {
			input:    "web-service-soap",
			expected: WebServiceSOAP,
		},
		"ejb": {
			input:    "ejb",
			expected: EJB,
		},
		"search-index": {
			input:    "search-index",
			expected: SearchIndex,
		},
		"search-engine": {
			input:    "search-engine",
			expected: SearchEngine,
		},
		"service-registry": {
			input:    "service-registry",
			expected: ServiceRegistry,
		},
		"reverse-proxy": {
			input:    "reverse-proxy",
			expected: ReverseProxy,
		},
		"load-balancer": {
			input:    "load-balancer",
			expected: LoadBalancer,
		},
		"build-pipeline": {
			input:    "build-pipeline",
			expected: BuildPipeline,
		},
		"sourcecode-repository": {
			input:    "sourcecode-repository",
			expected: SourcecodeRepository,
		},
		"artifact-registry": {
			input:    "artifact-registry",
			expected: ArtifactRegistry,
		},
		"code-inspection-platform": {
			input:    "code-inspection-platform",
			expected: CodeInspectionPlatform,
		},
		"monitoring": {
			input:    "monitoring",
			expected: Monitoring,
		},
		"ldap-server": {
			input:    "ldap-server",
			expected: LDAPServer,
		},
		"container-platform": {
			input:    "container-platform",
			expected: ContainerPlatform,
		},
		"batch-processing": {
			input:    "batch-processing",
			expected: BatchProcessing,
		},
		"event-listener": {
			input:    "event-listener",
			expected: EventListener,
		},
		"identity-provider": {
			input:    "identity-provider",
			expected: IdentityProvider,
		},
		"identity-store-ldap": {
			input:    "identity-store-ldap",
			expected: IdentityStoreLDAP,
		},
		"identity-store-database": {
			input:    "identity-store-database",
			expected: IdentityStoreDatabase,
		},
		"tool": {
			input:    "tool",
			expected: Tool,
		},
		"threagile": {
			input:    "threagile",
			expected: CLI,
		},
		"task": {
			input:    "task",
			expected: Task,
		},
		"function": {
			input:    "function",
			expected: Function,
		},
		"gateway": {
			input:    "gateway",
			expected: Gateway,
		},
		"iot-device": {
			input:    "iot-device",
			expected: IoTDevice,
		},
		"message-queue": {
			input:    "message-queue",
			expected: MessageQueue,
		},
		"stream-processing": {
			input:    "stream-processing",
			expected: StreamProcessing,
		},
		"service-mesh": {
			input:    "service-mesh",
			expected: ServiceMesh,
		},
		"data-lake": {
			input:    "data-lake",
			expected: DataLake,
		},
		"big-data-platform": {
			input:    "big-data-platform",
			expected: BigDataPlatform,
		},
		"report-engine": {
			input:    "report-engine",
			expected: ReportEngine,
		},
		"ai": {
			input:    "ai",
			expected: AI,
		},
		"mail-server": {
			input:    "mail-server",
			expected: MailServer,
		},
		"vault": {
			input:    "vault",
			expected: Vault,
		},
		"hsm": {
			input:    "hsm",
			expected: HSM,
		},
		"waf": {
			input:    "waf",
			expected: WAF,
		},
		"ids": {
			input:    "ids",
			expected: IDS,
		},
		"ips": {
			input:    "ips",
			expected: IPS,
		},
		"scheduler": {
			input:    "scheduler",
			expected: Scheduler,
		},
		"mainframe": {
			input:    "mainframe",
			expected: Mainframe,
		},
		"block-storage": {
			input:    "block-storage",
			expected: BlockStorage,
		},
		"library": {
			input:    "library",
			expected: Library,
		},
		"unknown": {
			input:         "unknown",
			expectedError: errors.New("Unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseTechnicalAssetTechnology(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
