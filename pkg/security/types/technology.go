package types

import "strings"

const (
	AI                     = "ai"
	ApplicationServer      = "application-server"
	ArtifactRegistry       = "artifact-registry"
	BatchProcessing        = "batch-processing"
	BigDataPlatform        = "big-data-platform"
	BlockStorage           = "block-storage"
	Browser                = "browser"
	BuildPipeline          = "build-pipeline"
	ClientSystem           = "client-system"
	CLI                    = "cli"
	CMS                    = "cms"
	CodeInspectionPlatform = "code-inspection-platform"
	ContainerPlatform      = "container-platform"
	DataLake               = "data-lake"
	Database               = "database"
	Desktop                = "desktop"
	DevOpsClient           = "devops-client"
	EJB                    = "ejb"
	ERP                    = "erp"
	EventListener          = "event-listener"
	FileServer             = "file-server"
	Function               = "function"
	Gateway                = "gateway"
	HSM                    = "hsm"
	IdentityProvider       = "identity-provider"
	IdentityStoreDatabase  = "identity-store-database"
	IdentityStoreLDAP      = "identity-store-ldap"
	IDS                    = "ids"
	IoTDevice              = "iot-device"
	IPS                    = "ips"
	LDAPServer             = "ldap-server"
	Library                = "library"
	LoadBalancer           = "load-balancer"
	LocalFileSystem        = "local-file-system"
	MailServer             = "mail-server"
	Mainframe              = "mainframe"
	MessageQueue           = "message-queue"
	MobileApp              = "mobile-app"
	Monitoring             = "monitoring"
	ReportEngine           = "report-engine"
	ReverseProxy           = "reverse-proxy"
	Scheduler              = "scheduler"
	SearchEngine           = "search-engine"
	SearchIndex            = "search-index"
	ServiceMesh            = "service-mesh"
	ServiceRegistry        = "service-registry"
	SourcecodeRepository   = "sourcecode-repository"
	StreamProcessing       = "stream-processing"
	Task                   = "task"
	Tool                   = "tool"
	UnknownTechnology      = "unknown-technology"
	Vault                  = "vault"
	WAF                    = "waf"
	WebApplication         = "web-application"
	WebServer              = "web-server"
	WebServiceREST         = "web-service-rest"
	WebServiceSOAP         = "web-service-soap"
)

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

func (what Technology) GetAttribute(name string) bool {
	value, valueOk := what.Attributes[name]
	if valueOk {
		return value
	}
	return false
}

func (what Technology) Explain() string {
	text := make([]string, 0)

	text = append(text, what.Description)

	if len(what.Aliases) > 0 {
		text = append(text, "Aliases: ")
		for _, alias := range what.Aliases {
			text = append(text, "  - "+alias)
		}
	}

	if len(what.Examples) > 0 {
		text = append(text, "Examples: ")
		for _, example := range what.Examples {
			text = append(text, "  - "+example)
		}
	}

	return strings.Join(text, "\n")
}
