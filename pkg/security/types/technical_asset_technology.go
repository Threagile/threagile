/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
)

type TechnicalAssetTechnology int

func TechnicalAssetTechnologyValues() []TypeEnum {
	return []TypeEnum{
		UnknownTechnology,
		ClientSystem,
		Browser,
		Desktop,
		MobileApp,
		DevOpsClient,
		WebServer,
		WebApplication,
		ApplicationServer,
		Database,
		FileServer,
		LocalFileSystem,
		ERP,
		CMS,
		WebServiceREST,
		WebServiceSOAP,
		EJB,
		SearchIndex,
		SearchEngine,
		ServiceRegistry,
		ReverseProxy,
		LoadBalancer,
		BuildPipeline,
		SourcecodeRepository,
		ArtifactRegistry,
		CodeInspectionPlatform,
		Monitoring,
		LDAPServer,
		ContainerPlatform,
		BatchProcessing,
		EventListener,
		IdentityProvider,
		IdentityStoreLDAP,
		IdentityStoreDatabase,
		Tool,
		CLI,
		Task,
		Function,
		Gateway,
		IoTDevice,
		MessageQueue,
		StreamProcessing,
		ServiceMesh,
		DataLake,
		BigDataPlatform,
		ReportEngine,
		AI,
		MailServer,
		Vault,
		HSM,
		WAF,
		IDS,
		IPS,
		Scheduler,
		Mainframe,
		BlockStorage,
		Library,
	}
}

var TechnicalAssetTechnologyTypeDescription = [...]TypeDescription{
	{"unknown-technology", "Unknown technology"},
	{"client-system", "A client system"},
	{"browser", "A web browser"},
	{"desktop", "A desktop system (or laptop)"},
	{"mobile-app", "A mobile app (smartphone, tablet)"},
	{"devops-client", "A client used for DevOps"},
	{"web-server", "A web server"},
	{"web-application", "A web application"},
	{"application-server", "An application server (Apache Tomcat, ...)"},
	{"database", "A database"},
	{"file-server", "A file server"},
	{"local-file-system", "The local file system"},
	{"erp", "Enterprise-Resource-Planning"},
	{"cms", "Content Management System"},
	{"web-service-rest", "A REST web service (API)"},
	{"web-service-soap", "A SOAP web service (API)"},
	{"ejb", "Jakarta Enterprise Beans fka Enterprise JavaBeans"},
	{"search-index", "The index database of a search engine"},
	{"search-engine", "A search engine"},
	{"service-registry", "A central place where data schemas can be found and distributed"},
	{"reverse-proxy", "A proxy hiding internal infrastructure from caller making requests. Can also reduce load"},
	{"load-balancer", "A load balancer directing incoming requests to available internal infrastructure"},
	{"build-pipeline", "A software build pipeline"},
	{"sourcecode-repository", "Git or similar"},
	{"artifact-registry", "A registry to store build artifacts"},
	{"code-inspection-platform", "(Static) Code Analysis)"},
	{"monitoring", "A monitoring system (SIEM, logs)"},
	{"ldap-server", "A LDAP server"},
	{"container-platform", "A platform for hosting and executing containers"},
	{"batch-processing", "A set of tools automatically processing data"},
	{"event-listener", "An event listener waiting to be triggered and spring to action"},
	{"identity-provider", "A authentication provider"},
	{"identity-store-ldap", "Authentication data as LDAP"},
	{"identity-store-database", "Authentication data as database"},
	{"tool", "A specific tool"},
	{"cli", "A command line tool"},
	{"task", "A specific task"},
	{"function", "A specific function (maybe RPC ?)"},
	{"gateway", "A gateway connecting two systems or trust boundaries"},
	{"iot-device", "An IoT device"},
	{"message-queue", "A message queue (like MQTT)"},
	{"stream-processing", "Data stream processing"},
	{"service-mesh", "Infrastructure for service-to-service communication"},
	{"data-lake", "A huge database"},
	{"big-data-platform", "Storage for big data"},
	{"report-engine", "Software for report generation"},
	{"ai", "An Artificial Intelligence service"},
	{"mail-server", "A Mail server"},
	{"vault", "Encryption and key management"},
	{"hsm", "Hardware Security Module"},
	{"waf", "Web Application Firewall"},
	{"ids", "Intrusion Detection System"},
	{"ips", "Intrusion Prevention System"},
	{"scheduler", "Scheduled tasks"},
	{"mainframe", "A central, big computer"},
	{"block-storage", "SAN or similar central file storage"},
	{"library", "A software library"},
}

func (what TechnicalAssetTechnology) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return TechnicalAssetTechnologyTypeDescription[what].Name
}

func (what TechnicalAssetTechnology) Explain() string {
	return TechnicalAssetTechnologyTypeDescription[what].Description
}

func ParseTechnicalAssetTechnology(value string) (technicalAssetTechnology TechnicalAssetTechnology, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range TechnicalAssetTechnologyValues() {
		if candidate.String() == value {
			return candidate.(TechnicalAssetTechnology), err
		}
	}
	return technicalAssetTechnology, fmt.Errorf("unable to parse into type: %v", value)
}

func (what TechnicalAssetTechnology) IsWebApplication() bool {
	switch what {
	case WebServer, WebApplication, ApplicationServer, ERP, CMS, IdentityProvider, ReportEngine:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsWebService() bool {
	switch what {
	case WebServiceREST, WebServiceSOAP:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsIdentityRelated() bool {
	switch what {
	case IdentityProvider, IdentityStoreLDAP, IdentityStoreDatabase:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsSecurityControlRelated() bool {
	switch what {
	case Vault, HSM, WAF, IDS, IPS:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsUnprotectedCommunicationsTolerated() bool {
	switch what {
	case Monitoring, IDS, IPS:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsUnnecessaryDataTolerated() bool {
	switch what {
	case Monitoring, IDS, IPS:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsCloseToHighValueTargetsTolerated() bool {
	switch what {
	case Monitoring, IDS, IPS, LoadBalancer, ReverseProxy:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsClient() bool {
	switch what {
	case ClientSystem, Browser, Desktop, MobileApp, DevOpsClient, IoTDevice:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsUsuallyAbleToPropagateIdentityToOutgoingTargets() bool {
	switch what {
	case ClientSystem, Browser, Desktop, MobileApp, DevOpsClient, Tool, CLI, IoTDevice: // client apps and devices
	case WebServer, WebApplication, ApplicationServer, WebServiceREST, WebServiceSOAP, EJB: // services
	case ERP, CMS, SearchEngine, ReportEngine: // systems
	case ReverseProxy, LoadBalancer, IdentityProvider, Gateway, ServiceMesh, WAF, MessageQueue: // infrastructure
	case Task, Function, Library: // other entities

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsLessProtectedType() bool {
	switch what {
	case ClientSystem, Browser, Desktop, MobileApp, DevOpsClient, IoTDevice: // client apps and devices
	case WebServer, WebApplication, ApplicationServer, WebServiceREST, WebServiceSOAP, EJB: // services
	case CMS: // systems
	case Monitoring, MailServer, Scheduler, Mainframe: // infrastructure
	case BuildPipeline, SourcecodeRepository, ArtifactRegistry, CodeInspectionPlatform: // devops
	case AI: // other entities

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsUsuallyProcessingEndUserRequests() bool {
	switch what {
	case WebServer, WebApplication, ApplicationServer, ERP, WebServiceREST, WebServiceSOAP, EJB, ReportEngine:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsUsuallyStoringEndUserData() bool {
	switch what {
	case Database, ERP, FileServer, LocalFileSystem, BlockStorage, MailServer, StreamProcessing, MessageQueue:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsExclusivelyFrontendRelated() bool {
	switch what {
	case ClientSystem, Browser, Desktop, MobileApp, DevOpsClient, CMS, ReverseProxy, WAF, LoadBalancer, Gateway, IoTDevice:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsExclusivelyBackendRelated() bool {
	switch what {
	case Database, IdentityProvider, IdentityStoreLDAP, IdentityStoreDatabase, ERP:
	case WebServiceREST, WebServiceSOAP, EJB:
	case SearchIndex, SearchEngine, ContainerPlatform, BatchProcessing, EventListener, DataLake, BigDataPlatform:
	case MessageQueue, StreamProcessing, ServiceMesh, Vault, HSM, Scheduler, Mainframe, FileServer, BlockStorage:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsDevelopmentRelevant() bool {
	switch what {
	case BuildPipeline, SourcecodeRepository, ArtifactRegistry, CodeInspectionPlatform, DevOpsClient:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsTrafficForwarding() bool {
	switch what {
	case LoadBalancer, ReverseProxy, WAF:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) IsEmbeddedComponent() bool {
	switch what {
	case Library:

	default:
		return false
	}

	return true
}

func (what TechnicalAssetTechnology) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *TechnicalAssetTechnology) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what TechnicalAssetTechnology) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *TechnicalAssetTechnology) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what TechnicalAssetTechnology) find(value string) (TechnicalAssetTechnology, error) {
	for index, description := range TechnicalAssetTechnologyTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return TechnicalAssetTechnology(index), nil
		}
	}

	return TechnicalAssetTechnology(0), fmt.Errorf("unknown technical asset technology value %q", value)
}
