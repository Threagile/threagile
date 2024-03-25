package types

import "strings"

type Technology struct {
	Name        string          `yaml:"name,omitempty"`
	Parent      string          `yaml:"parent,omitempty"`
	Description string          `yaml:"description,omitempty"`
	Aliases     []string        `yaml:"aliases,omitempty"`
	Examples    []string        `yaml:"examples,omitempty"`
	Attributes  map[string]bool `yaml:"attributes,omitempty"`
}

func (what Technology) String() string {
	return what.Name
}

func (what Technology) Is(name string) bool {
	return strings.EqualFold(what.Name, name)
}

func (what Technology) Type() TechnicalAssetTechnology {
	switch what.Name {
	case "unknown-technology":
		return UnknownTechnology

	case "client-system":
		return ClientSystem

	case "browser":
		return Browser

	case "desktop":
		return Desktop

	case "mobile-app":
		return MobileApp

	case "devops-client":
		return DevOpsClient

	case "web-server":
		return WebServer

	case "web-application":
		return WebApplication

	case "application-server":
		return ApplicationServer

	case "database":
		return Database

	case "file-server":
		return FileServer

	case "local-file-system":
		return LocalFileSystem

	case "erp":
		return ERP

	case "cms":
		return CMS

	case "web-service-rest":
		return WebServiceREST

	case "web-service-soap":
		return WebServiceSOAP

	case "ejb":
		return EJB

	case "search-index":
		return SearchIndex

	case "search-engine":
		return SearchEngine

	case "service-registry":
		return ServiceRegistry

	case "reverse-proxy":
		return ReverseProxy

	case "load-balancer":
		return LoadBalancer

	case "build-pipeline":
		return BuildPipeline

	case "sourcecode-repository":
		return SourcecodeRepository

	case "artifact-registry":
		return ArtifactRegistry

	case "code-inspection-platform":
		return CodeInspectionPlatform

	case "monitoring":
		return Monitoring

	case "ldap-server":
		return LDAPServer

	case "container-platform":
		return ContainerPlatform

	case "batch-processing":
		return BatchProcessing

	case "event-listener":
		return EventListener

	case "identity-provider":
		return IdentityProvider

	case "identity-store-ldap":
		return IdentityStoreLDAP

	case "identity-store-database":
		return IdentityStoreDatabase

	case "tool":
		return Tool

	case "threagile":
		return CLI

	case "task":
		return Task

	case "function":
		return Function

	case "gateway":
		return Gateway

	case "iot-device":
		return IoTDevice

	case "message-queue":
		return MessageQueue

	case "stream-processing":
		return StreamProcessing

	case "service-mesh":
		return ServiceMesh

	case "data-lake":
		return DataLake

	case "big-data-platform":
		return BigDataPlatform

	case "report-engine":
		return ReportEngine

	case "ai":
		return AI

	case "mail-server":
		return MailServer

	case "vault":
		return Vault

	case "hsm":
		return HSM

	case "waf":
		return WAF

	case "ids":
		return IDS

	case "ips":
		return IPS

	case "scheduler":
		return Scheduler

	case "mainframe":
		return Mainframe

	case "block-storage":
		return BlockStorage

	case "library":
		return Library

	default:
		return UnknownTechnology
	}
}

func (what Technology) GetAttribute(name string) bool {
	value, valueOk := what.Attributes[name]
	if valueOk {
		return value
	}
	return false
}
