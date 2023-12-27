/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type TechnicalAssetTechnology int

const (
	UnknownTechnology TechnicalAssetTechnology = iota
	ClientSystem
	Browser
	Desktop
	MobileApp
	DevOpsClient
	WebServer
	WebApplication
	ApplicationServer
	Database
	FileServer
	LocalFileSystem
	ERP
	CMS
	WebServiceREST
	WebServiceSOAP
	EJB
	SearchIndex
	SearchEngine
	ServiceRegistry
	ReverseProxy
	LoadBalancer
	BuildPipeline
	SourcecodeRepository
	ArtifactRegistry
	CodeInspectionPlatform
	Monitoring
	LDAPServer
	ContainerPlatform
	BatchProcessing
	EventListener
	IdentityProvider
	IdentityStoreLDAP
	IdentityStoreDatabase
	Tool
	CLI
	Task
	Function
	Gateway // TODO rename to API-Gateway to be more clear?
	IoTDevice
	MessageQueue
	StreamProcessing
	ServiceMesh
	DataLake
	BigDataPlatform
	ReportEngine
	AI
	MailServer
	Vault
	HSM
	WAF
	IDS
	IPS
	Scheduler
	Mainframe
	BlockStorage
	Library
)

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
	{"threagile", "A command line tool"},
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
	return technicalAssetTechnology, errors.New("Unable to parse into type: " + value)
}

func (what TechnicalAssetTechnology) IsWebApplication() bool {
	return what == WebServer || what == WebApplication || what == ApplicationServer || what == ERP || what == CMS || what == IdentityProvider || what == ReportEngine
}

func (what TechnicalAssetTechnology) IsWebService() bool {
	return what == WebServiceREST || what == WebServiceSOAP
}

func (what TechnicalAssetTechnology) IsIdentityRelated() bool {
	return what == IdentityProvider || what == IdentityStoreLDAP || what == IdentityStoreDatabase
}

func (what TechnicalAssetTechnology) IsSecurityControlRelated() bool {
	return what == Vault || what == HSM || what == WAF || what == IDS || what == IPS
}

func (what TechnicalAssetTechnology) IsUnprotectedCommunicationsTolerated() bool {
	return what == Monitoring || what == IDS || what == IPS
}

func (what TechnicalAssetTechnology) IsUnnecessaryDataTolerated() bool {
	return what == Monitoring || what == IDS || what == IPS
}

func (what TechnicalAssetTechnology) IsCloseToHighValueTargetsTolerated() bool {
	return what == Monitoring || what == IDS || what == IPS || what == LoadBalancer || what == ReverseProxy
}

func (what TechnicalAssetTechnology) IsClient() bool {
	return what == ClientSystem || what == Browser || what == Desktop || what == MobileApp || what == DevOpsClient || what == IoTDevice
}

func (what TechnicalAssetTechnology) IsUsuallyAbleToPropagateIdentityToOutgoingTargets() bool {
	return what == ClientSystem || what == Browser || what == Desktop || what == MobileApp ||
		what == DevOpsClient || what == WebServer || what == WebApplication || what == ApplicationServer || what == ERP ||
		what == CMS || what == WebServiceREST || what == WebServiceSOAP || what == EJB ||
		what == SearchEngine || what == ReverseProxy || what == LoadBalancer || what == IdentityProvider ||
		what == Tool || what == CLI || what == Task || what == Function || what == Gateway ||
		what == IoTDevice || what == MessageQueue || what == ServiceMesh || what == ReportEngine || what == WAF || what == Library

}

func (what TechnicalAssetTechnology) IsLessProtectedType() bool {
	return what == ClientSystem || what == Browser || what == Desktop || what == MobileApp || what == DevOpsClient || what == WebServer || what == WebApplication || what == ApplicationServer || what == CMS ||
		what == WebServiceREST || what == WebServiceSOAP || what == EJB || what == BuildPipeline || what == SourcecodeRepository ||
		what == ArtifactRegistry || what == CodeInspectionPlatform || what == Monitoring || what == IoTDevice || what == AI || what == MailServer || what == Scheduler ||
		what == Mainframe
}

func (what TechnicalAssetTechnology) IsUsuallyProcessingEndUserRequests() bool {
	return what == WebServer || what == WebApplication || what == ApplicationServer || what == ERP || what == WebServiceREST || what == WebServiceSOAP || what == EJB || what == ReportEngine
}

func (what TechnicalAssetTechnology) IsUsuallyStoringEndUserData() bool {
	return what == Database || what == ERP || what == FileServer || what == LocalFileSystem || what == BlockStorage || what == MailServer || what == StreamProcessing || what == MessageQueue
}

func (what TechnicalAssetTechnology) IsExclusivelyFrontendRelated() bool {
	return what == ClientSystem || what == Browser || what == Desktop || what == MobileApp || what == DevOpsClient || what == CMS || what == ReverseProxy || what == WAF || what == LoadBalancer || what == Gateway || what == IoTDevice
}

func (what TechnicalAssetTechnology) IsExclusivelyBackendRelated() bool {
	return what == Database || what == IdentityProvider || what == IdentityStoreLDAP || what == IdentityStoreDatabase || what == ERP || what == WebServiceREST || what == WebServiceSOAP || what == EJB || what == SearchIndex ||
		what == SearchEngine || what == ContainerPlatform || what == BatchProcessing || what == EventListener || what == DataLake || what == BigDataPlatform || what == MessageQueue ||
		what == StreamProcessing || what == ServiceMesh || what == Vault || what == HSM || what == Scheduler || what == Mainframe || what == FileServer || what == BlockStorage
}

func (what TechnicalAssetTechnology) IsDevelopmentRelevant() bool {
	return what == BuildPipeline || what == SourcecodeRepository || what == ArtifactRegistry || what == CodeInspectionPlatform || what == DevOpsClient
}

func (what TechnicalAssetTechnology) IsTrafficForwarding() bool {
	return what == LoadBalancer || what == ReverseProxy || what == WAF
}

func (what TechnicalAssetTechnology) IsEmbeddedComponent() bool {
	return what == Library
}

func (what TechnicalAssetTechnology) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *TechnicalAssetTechnology) UnmarshalJSON([]byte) error {
	for index, description := range TechnicalAssetTechnologyTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = TechnicalAssetTechnology(index)
			return nil
		}
	}

	return fmt.Errorf("unknown technical asset technology value %q", int(*what))
}
