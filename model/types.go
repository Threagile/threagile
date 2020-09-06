package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/threagile/threagile/colors"
	"regexp"
	"sort"
	"strings"
	"time"
)

const ThreagileVersion = "1.0.0" // Also update into example and stub model files and openapi.yaml
const TempFolder = "/dev/shm"    // TODO: make configurable via cmdline arg?

var ParsedModelRoot ParsedModel

var CommunicationLinks map[string]CommunicationLink // TODO as part of "ParsedModelRoot"?
var IncomingTechnicalCommunicationLinksMappedByTargetId map[string][]CommunicationLink
var DirectContainingTrustBoundaryMappedByTechnicalAssetId map[string]TrustBoundary
var DirectContainingSharedRuntimeMappedByTechnicalAssetId map[string]SharedRuntime

var GeneratedRisksByCategory map[RiskCategory][]Risk
var GeneratedRisksBySyntheticId map[string]Risk

var AllSupportedTags map[string]bool

func Init() {
	CommunicationLinks = make(map[string]CommunicationLink, 0)
	IncomingTechnicalCommunicationLinksMappedByTargetId = make(map[string][]CommunicationLink, 0)
	DirectContainingTrustBoundaryMappedByTechnicalAssetId = make(map[string]TrustBoundary, 0)
	DirectContainingSharedRuntimeMappedByTechnicalAssetId = make(map[string]SharedRuntime, 0)
	GeneratedRisksByCategory = make(map[RiskCategory][]Risk, 0)
	GeneratedRisksBySyntheticId = make(map[string]Risk, 0)
	AllSupportedTags = make(map[string]bool, 0)
}

func AddToListOfSupportedTags(tags []string) {
	for _, tag := range tags {
		AllSupportedTags[tag] = true
	}
}

type CustomRiskRule interface {
	Category() RiskCategory
	SupportedTags() []string
	GenerateRisks() []Risk
}

// === To be used by model macros etc. =======================

func AddTagToModelInput(modelInput *ModelInput, tag string, dryRun bool, changes *[]string) {
	tag = NormalizeTag(tag)
	if !Contains(modelInput.Tags_available, tag) {
		*changes = append(*changes, "adding tag: "+tag)
		if !dryRun {
			modelInput.Tags_available = append(modelInput.Tags_available, tag)
		}
	}
}

func NormalizeTag(tag string) string {
	return strings.TrimSpace(strings.ToLower(tag))
}

func MakeID(val string) string {
	reg, _ := regexp.Compile("[^A-Za-z0-9]+")
	return strings.Trim(reg.ReplaceAllString(strings.ToLower(val), "-"), "- ")
}

// === Model Type Stuff ======================================

type ModelInput struct { // TODO: Eventually remove this and directly use ParsedModelRoot? But then the error messages for model errors are not quite as good anymore...
	Threagile_version                                  string
	Title                                              string
	Author                                             Author
	Date                                               string
	Business_overview                                  Overview
	Technical_overview                                 Overview
	Business_criticality                               string
	Management_summary_comment                         string
	Questions                                          map[string]string
	Abuse_cases                                        map[string]string
	Security_requirements                              map[string]string
	Tags_available                                     []string
	Data_assets                                        map[string]InputDataAsset
	Technical_assets                                   map[string]InputTechnicalAsset
	Trust_boundaries                                   map[string]InputTrustBoundary
	Shared_runtimes                                    map[string]InputSharedRuntime
	Individual_risk_categories                         map[string]InputIndividualRiskCategory
	Risk_tracking                                      map[string]InputRiskTracking
	Diagram_tweak_nodesep, Diagram_tweak_ranksep       int
	Diagram_tweak_edge_layout                          string
	Diagram_tweak_suppress_edge_labels                 bool
	Diagram_tweak_layout_left_to_right                 bool
	Diagram_tweak_invisible_connections_between_assets []string
	Diagram_tweak_same_rank_assets                     []string
}

type InputDataAsset struct {
	ID                       string   `json:"id"`
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

type InputTechnicalAsset struct {
	ID                         string                            `json:"id"`
	Description                string                            `json:"description"`
	Type                       string                            `json:"type"`
	Usage                      string                            `json:"usage"`
	Used_as_client_by_human    bool                              `json:"used_as_client_by_human"`
	Out_of_scope               bool                              `json:"out_of_scope"`
	Justification_out_of_scope string                            `json:"justification_out_of_scope"`
	Size                       string                            `json:"size"`
	Technology                 string                            `json:"technology"`
	Tags                       []string                          `json:"tags"`
	Internet                   bool                              `json:"internet"`
	Machine                    string                            `json:"machine"`
	Encryption                 string                            `json:"encryption"`
	Owner                      string                            `json:"owner"`
	Confidentiality            string                            `json:"confidentiality"`
	Integrity                  string                            `json:"integrity"`
	Availability               string                            `json:"availability"`
	Justification_cia_rating   string                            `json:"justification_cia_rating"`
	Multi_tenant               bool                              `json:"multi_tenant"`
	Redundant                  bool                              `json:"redundant"`
	Custom_developed_parts     bool                              `json:"custom_developed_parts"`
	Data_assets_processed      []string                          `json:"data_assets_processed"`
	Data_assets_stored         []string                          `json:"data_assets_stored"`
	Data_formats_accepted      []string                          `json:"data_formats_accepted"`
	Diagram_tweak_order        int                               `json:"diagram_tweak_order"`
	Communication_links        map[string]InputCommunicationLink `json:"communication_links"`
}

type InputCommunicationLink struct {
	Target                   string   `json:"target"`
	Description              string   `json:"description"`
	Protocol                 string   `json:"protocol"`
	Authentication           string   `json:"authentication"`
	Authorization            string   `json:"authorization"`
	Tags                     []string `json:"tags"`
	VPN                      bool     `json:"vpn"`
	IP_filtered              bool     `json:"ip_filtered"`
	Readonly                 bool     `json:"readonly"`
	Usage                    string   `json:"usage"`
	Data_assets_sent         []string `json:"data_assets_sent"`
	Data_assets_received     []string `json:"data_assets_received"`
	Diagram_tweak_weight     int      `json:"diagram_tweak_weight"`
	Diagram_tweak_constraint bool     `json:"diagram_tweak_constraint"`
}

type InputSharedRuntime struct {
	ID                       string   `json:"id"`
	Description              string   `json:"description"`
	Tags                     []string `json:"tags"`
	Technical_assets_running []string `json:"technical_assets_running"`
}

type InputTrustBoundary struct {
	ID                      string   `json:"id"`
	Description             string   `json:"description"`
	Type                    string   `json:"type"`
	Tags                    []string `json:"tags"`
	Technical_assets_inside []string `json:"technical_assets_inside"`
	Trust_boundaries_nested []string `json:"trust_boundaries_nested"`
}

type InputIndividualRiskCategory struct {
	ID                            string                         `json:"id"`
	Description                   string                         `json:"description"`
	Impact                        string                         `json:"impact"`
	ASVS                          string                         `json:"asvs"`
	Cheat_sheet                   string                         `json:"cheat_sheet"`
	Action                        string                         `json:"action"`
	Mitigation                    string                         `json:"mitigation"`
	Check                         string                         `json:"check"`
	Function                      string                         `json:"function"`
	STRIDE                        string                         `json:"stride"`
	Detection_logic               string                         `json:"detection_logic"`
	Risk_assessment               string                         `json:"risk_assessment"`
	False_positives               string                         `json:"false_positives"`
	Model_failure_possible_reason bool                           `json:"model_failure_possible_reason"`
	CWE                           int                            `json:"cwe"`
	Risks_identified              map[string]InputRiskIdentified `json:"risks_identified"`
}

type InputRiskIdentified struct {
	Severity                         string   `json:"severity"`
	Exploitation_likelihood          string   `json:"exploitation_likelihood"`
	Exploitation_impact              string   `json:"exploitation_impact"`
	Data_breach_probability          string   `json:"data_breach_probability"`
	Data_breach_technical_assets     []string `json:"data_breach_technical_assets"`
	Most_relevant_data_asset         string   `json:"most_relevant_data_asset"`
	Most_relevant_technical_asset    string   `json:"most_relevant_technical_asset"`
	Most_relevant_communication_link string   `json:"most_relevant_communication_link"`
	Most_relevant_trust_boundary     string   `json:"most_relevant_trust_boundary"`
	Most_relevant_shared_runtime     string   `json:"most_relevant_shared_runtime"`
}

type InputRiskTracking struct {
	Status        string `json:"status"`
	Justification string `json:"justification"`
	Ticket        string `json:"ticket"`
	Date          string `json:"date"`
	Checked_by    string `json:"checked_by"`
}

type TypeEnum interface {
	String() string
}

type Quantity int

const (
	VeryFew Quantity = iota
	Few
	Many
	VeryMany
)

func QuantityValues() []TypeEnum {
	return []TypeEnum{
		VeryFew,
		Few,
		Many,
		VeryMany,
	}
}

func ParseQuantity(value string) (quantity Quantity, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range QuantityValues() {
		if candidate.String() == value {
			return candidate.(Quantity), err
		}
	}
	return quantity, errors.New("Unable to parse into type: " + value)
}

func (what Quantity) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"very-few", "few", "many", "very-many"}[what]
}

func (what Quantity) Title() string {
	return [...]string{"very few", "few", "many", "very many"}[what]
}

func (what Quantity) QuantityFactor() float64 {
	// fibonacci starting at 1
	return [...]float64{1, 2, 3, 5}[what]
}

type Confidentiality int

const (
	Public Confidentiality = iota
	Internal
	Restricted
	Confidential
	StrictlyConfidential
)

func ConfidentialityValues() []TypeEnum {
	return []TypeEnum{
		Public,
		Internal,
		Restricted,
		Confidential,
		StrictlyConfidential,
	}
}

func ParseConfidentiality(value string) (confidentiality Confidentiality, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range ConfidentialityValues() {
		if candidate.String() == value {
			return candidate.(Confidentiality), err
		}
	}
	return confidentiality, errors.New("Unable to parse into type: " + value)
}

func (what Confidentiality) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"public", "internal", "restricted", "confidential", "strictly-confidential"}[what]
}

func (what Confidentiality) AttackerAttractivenessForAsset() float64 {
	// fibonacci starting at 8
	return [...]float64{8, 13, 21, 34, 55}[what]
}
func (what Confidentiality) AttackerAttractivenessForProcessedOrStoredData() float64 {
	// fibonacci starting at 5
	return [...]float64{5, 8, 13, 21, 34}[what]
}
func (what Confidentiality) AttackerAttractivenessForInOutTransferredData() float64 {
	// fibonacci starting at 2
	return [...]float64{2, 3, 5, 8, 13}[what]
}

func (what Confidentiality) RatingStringInScale() string {
	result := "(rated "
	if what == Public {
		result += "1"
	}
	if what == Internal {
		result += "2"
	}
	if what == Restricted {
		result += "3"
	}
	if what == Confidential {
		result += "4"
	}
	if what == StrictlyConfidential {
		result += "5"
	}
	result += " in scale of 5)"
	return result
}

type Criticality int

const (
	Archive Criticality = iota
	Operational
	Important
	Critical
	MissionCritical
)

func CriticalityValues() []TypeEnum {
	return []TypeEnum{
		Archive,
		Operational,
		Important,
		Critical,
		MissionCritical,
	}
}

func ParseCriticality(value string) (criticality Criticality, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range CriticalityValues() {
		if candidate.String() == value {
			return candidate.(Criticality), err
		}
	}
	return criticality, errors.New("Unable to parse into type: " + value)
}

func (what Criticality) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"archive", "operational", "important", "critical", "mission-critical"}[what]
}

func (what Criticality) AttackerAttractivenessForAsset() float64 {
	// fibonacci starting at 5
	return [...]float64{5, 8, 13, 21, 34}[what]
}
func (what Criticality) AttackerAttractivenessForProcessedOrStoredData() float64 {
	// fibonacci starting at 3
	return [...]float64{3, 5, 8, 13, 21}[what]
}
func (what Criticality) AttackerAttractivenessForInOutTransferredData() float64 {
	// fibonacci starting at 2
	return [...]float64{2, 3, 5, 8, 13}[what]
}

func (what Criticality) RatingStringInScale() string {
	result := "(rated "
	if what == Archive {
		result += "1"
	}
	if what == Operational {
		result += "2"
	}
	if what == Important {
		result += "3"
	}
	if what == Critical {
		result += "4"
	}
	if what == MissionCritical {
		result += "5"
	}
	result += " in scale of 5)"
	return result
}

type TechnicalAssetType int

const (
	ExternalEntity TechnicalAssetType = iota
	Process
	Datastore
)

func TechnicalAssetTypeValues() []TypeEnum {
	return []TypeEnum{
		ExternalEntity,
		Process,
		Datastore,
	}
}

func (what TechnicalAssetType) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"external-entity", "process", "datastore"}[what]
}

type TechnicalAssetSize int

const (
	System TechnicalAssetSize = iota
	Service
	Application
	Component
)

func TechnicalAssetSizeValues() []TypeEnum {
	return []TypeEnum{
		System,
		Service,
		Application,
		Component,
	}
}

func (what TechnicalAssetSize) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"system", "service", "application", "component"}[what]
}

type Authorization int

const (
	NoneAuthorization Authorization = iota
	TechnicalUser
	EnduserIdentityPropagation
)

func AuthorizationValues() []TypeEnum {
	return []TypeEnum{
		NoneAuthorization,
		TechnicalUser,
		EnduserIdentityPropagation,
	}
}

func (what Authorization) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"none", "technical-user", "enduser-identity-propagation"}[what]
}

type Authentication int

const (
	NoneAuthentication Authentication = iota
	Credentials
	SessionId
	Token
	ClientCertificate
	TwoFactor
	Externalized
)

func AuthenticationValues() []TypeEnum {
	return []TypeEnum{
		NoneAuthentication,
		Credentials,
		SessionId,
		Token,
		ClientCertificate,
		TwoFactor,
		Externalized,
	}
}

func (what Authentication) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"none", "credentials", "session-id", "token", "client-certificate", "two-factor", "externalized"}[what]
}

type Usage int

const (
	Business Usage = iota
	DevOps
)

func UsageValues() []TypeEnum {
	return []TypeEnum{
		Business,
		DevOps,
	}
}

func ParseUsage(value string) (usage Usage, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range UsageValues() {
		if candidate.String() == value {
			return candidate.(Usage), err
		}
	}
	return usage, errors.New("Unable to parse into type: " + value)
}

func (what Usage) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"business", "devops"}[what]
}

func (what Usage) Title() string {
	return [...]string{"Business", "DevOps"}[what]
}

type EncryptionStyle int

const (
	NoneEncryption EncryptionStyle = iota
	Transparent
	DataWithSymmetricSharedKey
	DataWithAsymmetricSharedKey
	DataWithEnduserIndividualKey
)

func EncryptionStyleValues() []TypeEnum {
	return []TypeEnum{
		NoneEncryption,
		Transparent,
		DataWithSymmetricSharedKey,
		DataWithAsymmetricSharedKey,
		DataWithEnduserIndividualKey,
	}
}

func ParseEncryptionStyle(value string) (encryptionStyle EncryptionStyle, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range EncryptionStyleValues() {
		if candidate.String() == value {
			return candidate.(EncryptionStyle), err
		}
	}
	return encryptionStyle, errors.New("Unable to parse into type: " + value)
}

func (what EncryptionStyle) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"none", "transparent", "data-with-symmetric-shared-key", "data-with-asymmetric-shared-key", "data-with-enduser-individual-key"}[what]
}

func (what EncryptionStyle) Title() string {
	return [...]string{"None", "Transparent", "Data with Symmetric Shared Key", "Data with Asymmetric Shared Key", "Data with Enduser Individual Key"}[what]
}

type DataFormat int

const (
	JSON DataFormat = iota
	XML
	Serialization
	File
	CSV
)

func DataFormatValues() []TypeEnum {
	return []TypeEnum{
		JSON,
		XML,
		Serialization,
		File,
		CSV,
	}
}

func (what DataFormat) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"json", "xml", "serialization", "file", "csv"}[what]
}

func (what DataFormat) Title() string {
	return [...]string{"JSON", "XML", "Serialization", "File", "CSV"}[what]
}

func (what DataFormat) Description() string {
	return [...]string{"JSON marshalled object data", "XML structured data", "Serialization-based object graphs",
		"File input/uploads", "CSV tabular data"}[what]
}

type Protocol int

const (
	UnknownProtocol Protocol = iota
	HTTP
	HTTPS
	WS
	WSS
	Reverse_proxy_web_protocol
	Reverse_proxy_web_protocol_encrypted
	MQTT
	JDBC
	JDBC_encrypted
	ODBC
	ODBC_encrypted
	SQL_access_protocol
	SQL_access_protocol_encrypted
	NoSQL_access_protocol
	NoSQL_access_protocol_encrypted
	BINARY
	BINARY_encrypted
	TEXT
	TEXT_encrypted
	SSH
	SSH_tunnel
	SMTP
	SMTP_encrypted
	POP3
	POP3_encrypted
	IMAP
	IMAP_encrypted
	FTP
	FTPS
	SFTP
	SCP
	LDAP
	LDAPS
	JMS
	NFS
	SMB
	SMB_encrypted
	LocalFileAccess
	NRPE
	XMPP
	IIOP
	IIOP_encrypted
	JRMP
	JRMP_encrypted
	InProcessLibraryCall
	ContainerSpawning
)

func ProtocolValues() []TypeEnum {
	return []TypeEnum{
		UnknownProtocol,
		HTTP,
		HTTPS,
		WS,
		WSS,
		Reverse_proxy_web_protocol,
		Reverse_proxy_web_protocol_encrypted,
		MQTT,
		JDBC,
		JDBC_encrypted,
		ODBC,
		ODBC_encrypted,
		SQL_access_protocol,
		SQL_access_protocol_encrypted,
		NoSQL_access_protocol,
		NoSQL_access_protocol_encrypted,
		BINARY,
		BINARY_encrypted,
		TEXT,
		TEXT_encrypted,
		SSH,
		SSH_tunnel,
		SMTP,
		SMTP_encrypted,
		POP3,
		POP3_encrypted,
		IMAP,
		IMAP_encrypted,
		FTP,
		FTPS,
		SFTP,
		SCP,
		LDAP,
		LDAPS,
		JMS,
		NFS,
		SMB,
		SMB_encrypted,
		LocalFileAccess,
		NRPE,
		XMPP,
		IIOP,
		IIOP_encrypted,
		JRMP,
		JRMP_encrypted,
		InProcessLibraryCall,
		ContainerSpawning,
	}
}

func (what Protocol) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unknown-protocol", "http", "https", "ws", "wss", "reverse-proxy-web-protocol", "reverse-proxy-web-protocol-encrypted",
		"mqtt", "jdbc", "jdbc-encrypted", "odbc", "odbc-encrypted",
		"sql-access-protocol", "sql-access-protocol-encrypted", "nosql-access-protocol", "nosql-access-protocol-encrypted", "binary", "binary-encrypted", "text", "text-encrypted",
		"ssh", "ssh-tunnel", "smtp", "smtp-encrypted", "pop3", "pop3-encrypted", "imap", "imap-encrypted", "ftp", "ftps", "sftp", "scp", "ldap", "ldaps", "jms", "nfs", "smb", "smb-encrypted", "local-file-access", "nrpe", "xmpp",
		"iiop", "iiop-encrypted", "jrmp", "jrmp-encrypted", "in-process-library-call", "container-spawning"}[what]
}

func (what Protocol) IsProcessLocal() bool {
	return what == InProcessLibraryCall || what == LocalFileAccess || what == ContainerSpawning
}

func (what Protocol) IsEncrypted() bool {
	return what == HTTPS || what == WSS || what == JDBC_encrypted || what == ODBC_encrypted ||
		what == NoSQL_access_protocol_encrypted || what == SQL_access_protocol_encrypted || what == BINARY_encrypted || what == TEXT_encrypted || what == SSH || what == SSH_tunnel ||
		what == FTPS || what == SFTP || what == SCP || what == LDAPS || what == Reverse_proxy_web_protocol_encrypted ||
		what == IIOP_encrypted || what == JRMP_encrypted || what == SMB_encrypted || what == SMTP_encrypted || what == POP3_encrypted || what == IMAP_encrypted
}

func (what Protocol) IsPotentialDatabaseAccessProtocol(includingLaxDatabaseProtocols bool) bool {
	strictlyDatabaseOnlyProtocol := what == JDBC_encrypted || what == ODBC_encrypted ||
		what == NoSQL_access_protocol_encrypted || what == SQL_access_protocol_encrypted || what == JDBC || what == ODBC || what == NoSQL_access_protocol || what == SQL_access_protocol
	if includingLaxDatabaseProtocols {
		// include HTTP for REST-based NoSQL-DBs as well as unknown binary
		return strictlyDatabaseOnlyProtocol || what == HTTPS || what == HTTP || what == BINARY || what == BINARY_encrypted
	}
	return strictlyDatabaseOnlyProtocol
}

func (what Protocol) IsPotentialWebAccessProtocol() bool {
	return what == HTTP || what == HTTPS || what == WS || what == WSS || what == Reverse_proxy_web_protocol || what == Reverse_proxy_web_protocol_encrypted
}

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

func (what TechnicalAssetTechnology) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unknown-technology", "client-system", "browser", "desktop", "mobile-app", "devops-client",
		"web-server", "web-application", "application-server", "database", "file-server", "local-file-system", "erp", "cms",
		"web-service-rest", "web-service-soap", "ejb", "search-index", "search-engine", "service-registry", "reverse-proxy",
		"load-balancer", "build-pipeline", "sourcecode-repository", "artifact-registry", "code-inspection-platform", "monitoring", "ldap-server",
		"container-platform", "batch-processing", "event-listener", "identity-provider", "identity-store-ldap",
		"identity-store-database", "tool", "cli", "task", "function", "gateway", "iot-device", "message-queue", "stream-processing",
		"service-mesh", "data-lake", "big-data-platform", "report-engine", "ai", "mail-server", "vault", "hsm", "waf", "ids", "ips",
		"scheduler", "mainframe", "block-storage", "library"}[what]
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

func (what TechnicalAssetTechnology) IsUnprotectedCommsTolerated() bool {
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

func (what TechnicalAssetTechnology) IsUsuallyProcessingEnduserRequests() bool {
	return what == WebServer || what == WebApplication || what == ApplicationServer || what == ERP || what == WebServiceREST || what == WebServiceSOAP || what == EJB || what == ReportEngine
}

func (what TechnicalAssetTechnology) IsUsuallyStoringEnduserData() bool {
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

type TechnicalAssetMachine int

const (
	Physical TechnicalAssetMachine = iota
	Virtual
	Container
	Serverless
)

func TechnicalAssetMachineValues() []TypeEnum {
	return []TypeEnum{
		Physical,
		Virtual,
		Container,
		Serverless,
	}
}

func (what TechnicalAssetMachine) String() string {
	return [...]string{"physical", "virtual", "container", "serverless"}[what]
}

type TrustBoundaryType int

const (
	NetworkOnPrem TrustBoundaryType = iota
	NetworkDedicatedHoster
	NetworkVirtualLAN
	NetworkCloudProvider
	NetworkCloudSecurityGroup
	NetworkPolicyNamespaceIsolation
	ExecutionEnvironment
)

func TrustBoundaryTypeValues() []TypeEnum {
	return []TypeEnum{
		NetworkOnPrem,
		NetworkDedicatedHoster,
		NetworkVirtualLAN,
		NetworkCloudProvider,
		NetworkCloudSecurityGroup,
		NetworkPolicyNamespaceIsolation,
		ExecutionEnvironment,
	}
}

func (what TrustBoundaryType) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"network-on-prem", "network-dedicated-hoster", "network-virtual-lan",
		"network-cloud-provider", "network-cloud-security-group", "network-policy-namespace-isolation",
		"execution-environment"}[what]
}

func (what TrustBoundaryType) IsNetworkBoundary() bool {
	return what == NetworkOnPrem || what == NetworkDedicatedHoster || what == NetworkVirtualLAN ||
		what == NetworkCloudProvider || what == NetworkCloudSecurityGroup || what == NetworkPolicyNamespaceIsolation
}

func (what TrustBoundaryType) IsWithinCloud() bool {
	return what == NetworkCloudProvider || what == NetworkCloudSecurityGroup
}

func (what TrustBoundary) RecursivelyAllTechnicalAssetIDsInside() []string {
	result := make([]string, 0)
	what.addAssetIDsRecursively(&result)
	return result
}

func (what TrustBoundary) addAssetIDsRecursively(result *[]string) {
	*result = append(*result, what.TechnicalAssetsInside...)
	for _, nestedBoundaryID := range what.TrustBoundariesNested {
		ParsedModelRoot.TrustBoundaries[nestedBoundaryID].addAssetIDsRecursively(result)
	}
}

func (what TrustBoundary) AllParentTrustBoundaryIDs() []string {
	result := make([]string, 0)
	what.addTrustBoundaryIDsRecursively(&result)
	return result
}

func (what TrustBoundary) addTrustBoundaryIDsRecursively(result *[]string) {
	*result = append(*result, what.Id)
	parentID := what.ParentTrustBoundaryID()
	if len(parentID) > 0 {
		ParsedModelRoot.TrustBoundaries[parentID].addTrustBoundaryIDsRecursively(result)
	}
}

func IsSharingSameParentTrustBoundary(left, right TechnicalAsset) bool {
	tbIDLeft, tbIDRight := left.GetTrustBoundaryId(), right.GetTrustBoundaryId()
	if len(tbIDLeft) == 0 && len(tbIDRight) > 0 {
		return false
	}
	if len(tbIDLeft) > 0 && len(tbIDRight) == 0 {
		return false
	}
	if len(tbIDLeft) == 0 && len(tbIDRight) == 0 {
		return true
	}
	if tbIDLeft == tbIDRight {
		return true
	}
	tbLeft, tbRight := ParsedModelRoot.TrustBoundaries[tbIDLeft], ParsedModelRoot.TrustBoundaries[tbIDRight]
	tbParentsLeft, tbParentsRight := tbLeft.AllParentTrustBoundaryIDs(), tbRight.AllParentTrustBoundaryIDs()
	for _, parentLeft := range tbParentsLeft {
		for _, parentRight := range tbParentsRight {
			if parentLeft == parentRight {
				return true
			}
		}
	}
	return false
}

type DataAsset struct {
	Id                      string `json:"id"`          // TODO: tag here still required?
	Title                   string `json:"title"`       // TODO: tag here still required?
	Description             string `json:"description"` // TODO: tag here still required?
	Usage                   Usage
	Tags                    []string
	Origin, Owner           string
	Quantity                Quantity
	Confidentiality         Confidentiality
	Integrity, Availability Criticality
	JustificationCiaRating  string
}

func (what DataAsset) IsTaggedWithAny(tags ...string) bool {
	return ContainsCaseInsensitiveAny(what.Tags, tags...)
}

func (what DataAsset) IsTaggedWithBaseTag(basetag string) bool {
	return IsTaggedWithBaseTag(what.Tags, basetag)
}

/*
func (what DataAsset) IsAtRisk() bool {
	for _, techAsset := range what.ProcessedByTechnicalAssetsSorted() {
		if len(ReduceToOnlyStillAtRisk(techAsset.GeneratedRisks())) > 0 {
			return true
		}
	}
	for _, techAsset := range what.StoredByTechnicalAssetsSorted() {
		if len(ReduceToOnlyStillAtRisk(techAsset.GeneratedRisks())) > 0 {
			return true
		}
	}
	return false
}
*/
/*
func (what DataAsset) IdentifiedRiskSeverityStillAtRisk() RiskSeverity {
	highestRiskSeverity := Low
	for _, techAsset := range what.ProcessedByTechnicalAssetsSorted() {
		candidateSeverity := HighestSeverityStillAtRisk(ReduceToOnlyStillAtRisk(techAsset.GeneratedRisks()))
		if candidateSeverity > highestRiskSeverity {
			highestRiskSeverity = candidateSeverity
		}
	}
	for _, techAsset := range what.StoredByTechnicalAssetsSorted() {
		candidateSeverity := HighestSeverityStillAtRisk(ReduceToOnlyStillAtRisk(techAsset.GeneratedRisks()))
		if candidateSeverity > highestRiskSeverity {
			highestRiskSeverity = candidateSeverity
		}
	}
	return highestRiskSeverity
}
*/
func (what DataAsset) IdentifiedRisksByResponsibleTechnicalAssetId() map[string][]Risk {
	uniqueTechAssetIDsResponsibleForThisDataAsset := make(map[string]interface{})
	for _, techAsset := range what.ProcessedByTechnicalAssetsSorted() {
		if len(techAsset.GeneratedRisks()) > 0 {
			uniqueTechAssetIDsResponsibleForThisDataAsset[techAsset.Id] = true
		}
	}
	for _, techAsset := range what.StoredByTechnicalAssetsSorted() {
		if len(techAsset.GeneratedRisks()) > 0 {
			uniqueTechAssetIDsResponsibleForThisDataAsset[techAsset.Id] = true
		}
	}

	result := make(map[string][]Risk)
	for techAssetId, _ := range uniqueTechAssetIDsResponsibleForThisDataAsset {
		result[techAssetId] = append(result[techAssetId], ParsedModelRoot.TechnicalAssets[techAssetId].GeneratedRisks()...)
	}
	return result
}

func (what DataAsset) IsDataBreachPotentialStillAtRisk() bool {
	for _, risk := range FilteredByStillAtRisk() {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				return true
			}
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				return true
			}
		}
	}
	return false
}

func (what DataAsset) IdentifiedDataBreachProbability() DataBreachProbability {
	highestProbability := Improbable
	for _, risk := range AllRisks() {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
		}
	}
	return highestProbability
}

func (what DataAsset) IdentifiedDataBreachProbabilityStillAtRisk() DataBreachProbability {
	highestProbability := Improbable
	for _, risk := range FilteredByStillAtRisk() {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
		}
	}
	return highestProbability
}

func (what DataAsset) IdentifiedDataBreachProbabilityRisksStillAtRisk() []Risk {
	result := make([]Risk, 0)
	for _, risk := range FilteredByStillAtRisk() {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				result = append(result, risk)
				break
			}
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				result = append(result, risk)
				break
			}
		}
	}
	return result
}

func (what DataAsset) IdentifiedDataBreachProbabilityRisks() []Risk {
	result := make([]Risk, 0)
	for _, risk := range AllRisks() {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				result = append(result, risk)
				break
			}
			if Contains(ParsedModelRoot.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				result = append(result, risk)
				break
			}
		}
	}
	return result
}

func (what DataAsset) ProcessedByTechnicalAssetsSorted() []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, technicalAsset := range ParsedModelRoot.TechnicalAssets {
		for _, candidateID := range technicalAsset.DataAssetsProcessed {
			if candidateID == what.Id {
				result = append(result, technicalAsset)
			}
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(result))
	return result
}

func (what DataAsset) StoredByTechnicalAssetsSorted() []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, technicalAsset := range ParsedModelRoot.TechnicalAssets {
		for _, candidateID := range technicalAsset.DataAssetsStored {
			if candidateID == what.Id {
				result = append(result, technicalAsset)
			}
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(result))
	return result
}

func (what DataAsset) SentViaCommLinksSorted() []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, technicalAsset := range ParsedModelRoot.TechnicalAssets {
		for _, commLink := range technicalAsset.CommunicationLinks {
			for _, candidateID := range commLink.DataAssetsSent {
				if candidateID == what.Id {
					result = append(result, commLink)
				}
			}
		}
	}
	sort.Sort(ByTechnicalCommunicationLinkTitleSort(result))
	return result
}

func (what DataAsset) ReceivedViaCommLinksSorted() []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, technicalAsset := range ParsedModelRoot.TechnicalAssets {
		for _, commLink := range technicalAsset.CommunicationLinks {
			for _, candidateID := range commLink.DataAssetsReceived {
				if candidateID == what.Id {
					result = append(result, commLink)
				}
			}
		}
	}
	sort.Sort(ByTechnicalCommunicationLinkTitleSort(result))
	return result
}

func IsTaggedWithBaseTag(tags []string, basetag string) bool { // basetags are before the colon ":" like in "aws:ec2" it's "aws". The subtag is after the colon. Also a pure "aws" tag matches the basetag "aws"
	basetag = strings.ToLower(strings.TrimSpace(basetag))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == basetag || strings.HasPrefix(tag, basetag+":") {
			return true
		}
	}
	return false
}

type TechnicalAsset struct {
	Id, Title, Description                                                                  string
	Usage                                                                                   Usage
	Type                                                                                    TechnicalAssetType
	Size                                                                                    TechnicalAssetSize
	Technology                                                                              TechnicalAssetTechnology
	Machine                                                                                 TechnicalAssetMachine
	Internet, MultiTenant, Redundant, CustomDevelopedParts, OutOfScope, UsedAsClientByHuman bool
	Encryption                                                                              EncryptionStyle
	JustificationOutOfScope                                                                 string
	Owner                                                                                   string
	Confidentiality                                                                         Confidentiality
	Integrity, Availability                                                                 Criticality
	JustificationCiaRating                                                                  string
	Tags, DataAssetsProcessed, DataAssetsStored                                             []string
	DataFormatsAccepted                                                                     []DataFormat
	CommunicationLinks                                                                      []CommunicationLink
	DiagramTweakOrder                                                                       int
	// will be set by separate calculation step:
	RAA float64
}

func (what TechnicalAsset) IsTaggedWithAny(tags ...string) bool {
	return ContainsCaseInsensitiveAny(what.Tags, tags...)
}

func (what TechnicalAsset) IsTaggedWithBaseTag(basetag string) bool {
	return IsTaggedWithBaseTag(what.Tags, basetag)
}

// first use the tag(s) of the asset itself, then their trust boundaries (recursively up) and then their shared runtime
func (what TechnicalAsset) IsTaggedWithAnyTraversingUp(tags ...string) bool {
	if ContainsCaseInsensitiveAny(what.Tags, tags...) {
		return true
	}
	tbID := what.GetTrustBoundaryId()
	if len(tbID) > 0 {
		if ParsedModelRoot.TrustBoundaries[tbID].IsTaggedWithAnyTraversingUp(tags...) {
			return true
		}
	}
	for _, sr := range ParsedModelRoot.SharedRuntimes {
		if Contains(sr.TechnicalAssetsRunning, what.Id) && sr.IsTaggedWithAny(tags...) {
			return true
		}
	}
	return false
}

func (what TechnicalAsset) IsSameTrustBoundary(otherAssetId string) bool {
	trustBoundaryOfMyAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.Id]
	trustBoundaryOfOtherAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}

func (what TechnicalAsset) IsSameExecutionEnvironment(otherAssetId string) bool {
	trustBoundaryOfMyAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.Id]
	trustBoundaryOfOtherAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if trustBoundaryOfMyAsset.Type == ExecutionEnvironment && trustBoundaryOfOtherAsset.Type == ExecutionEnvironment {
		return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
	}
	return false
}

func (what TechnicalAsset) IsSameTrustBoundaryNetworkOnly(otherAssetId string) bool {
	trustBoundaryOfMyAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.Id]
	if !trustBoundaryOfMyAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfMyAsset = ParsedModelRoot.TrustBoundaries[trustBoundaryOfMyAsset.ParentTrustBoundaryID()]
	}
	trustBoundaryOfOtherAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if !trustBoundaryOfOtherAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfOtherAsset = ParsedModelRoot.TrustBoundaries[trustBoundaryOfOtherAsset.ParentTrustBoundaryID()]
	}
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}

func (what TechnicalAsset) HighestSensitivityScore() float64 {
	return what.Confidentiality.AttackerAttractivenessForAsset() +
		what.Integrity.AttackerAttractivenessForAsset() +
		what.Availability.AttackerAttractivenessForAsset()
}

func (what TechnicalAsset) HighestConfidentiality() Confidentiality {
	highest := what.Confidentiality
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	for _, dataId := range what.DataAssetsStored {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	return highest
}

func (what TechnicalAsset) DataAssetsProcessedSorted() []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsProcessed {
		result = append(result, ParsedModelRoot.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (what TechnicalAsset) DataAssetsStoredSorted() []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsStored {
		result = append(result, ParsedModelRoot.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (what TechnicalAsset) DataFormatsAcceptedSorted() []DataFormat {
	result := make([]DataFormat, 0)
	for _, format := range what.DataFormatsAccepted {
		result = append(result, format)
	}
	sort.Sort(ByDataFormatAcceptedSort(result))
	return result
}

func (what TechnicalAsset) CommunicationLinksSorted() []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, format := range what.CommunicationLinks {
		result = append(result, format)
	}
	sort.Sort(ByTechnicalCommunicationLinkTitleSort(result))
	return result
}

func (what TechnicalAsset) HighestIntegrity() Criticality {
	highest := what.Integrity
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	for _, dataId := range what.DataAssetsStored {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	return highest
}

func (what TechnicalAsset) HighestAvailability() Criticality {
	highest := what.Availability
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	for _, dataId := range what.DataAssetsStored {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	return highest
}

func (what TechnicalAsset) HasDirectConnection(otherAssetId string) bool {
	for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
		if dataFlow.SourceId == otherAssetId {
			return true
		}
	}
	// check both directions, hence two times, just reversed
	for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[otherAssetId] {
		if dataFlow.SourceId == what.Id {
			return true
		}
	}
	return false
}

func (what TechnicalAsset) GeneratedRisks() []Risk {
	resultingRisks := make([]Risk, 0)
	if len(SortedRiskCategories()) == 0 {
		fmt.Println("Uh, strange, no risks generated (yet?) and asking for them by tech asset...")
	}
	for _, category := range SortedRiskCategories() {
		risks := SortedRisksOfCategory(category)
		for _, risk := range risks {
			if risk.MostRelevantTechnicalAssetId == what.Id {
				resultingRisks = append(resultingRisks, risk)
			}
		}
	}
	sort.Sort(ByRiskSeveritySort(resultingRisks))
	return resultingRisks
}

/*
func (what TechnicalAsset) HighestRiskSeverity() RiskSeverity {
	highest := Low
	for _, risk := range what.GeneratedRisks() {
		if risk.Severity > highest {
			highest = risk.Severity
		}
	}
	return highest
}
*/

type ByDataAssetDataBreachProbabilityAndTitleSort []DataAsset

func (what ByDataAssetDataBreachProbabilityAndTitleSort) Len() int { return len(what) }
func (what ByDataAssetDataBreachProbabilityAndTitleSort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByDataAssetDataBreachProbabilityAndTitleSort) Less(i, j int) bool {
	highestDataBreachProbabilityLeft := what[i].IdentifiedDataBreachProbability()
	highestDataBreachProbabilityRight := what[j].IdentifiedDataBreachProbability()
	if highestDataBreachProbabilityLeft == highestDataBreachProbabilityRight {
		return what[i].Title < what[j].Title
	}
	return highestDataBreachProbabilityLeft > highestDataBreachProbabilityRight
}

type ByDataAssetDataBreachProbabilityAndTitleSortStillAtRisk []DataAsset

func (what ByDataAssetDataBreachProbabilityAndTitleSortStillAtRisk) Len() int { return len(what) }
func (what ByDataAssetDataBreachProbabilityAndTitleSortStillAtRisk) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByDataAssetDataBreachProbabilityAndTitleSortStillAtRisk) Less(i, j int) bool {
	risksLeft := what[i].IdentifiedDataBreachProbabilityRisksStillAtRisk()
	risksRight := what[j].IdentifiedDataBreachProbabilityRisksStillAtRisk()
	highestDataBreachProbabilityLeft := what[i].IdentifiedDataBreachProbabilityStillAtRisk()
	highestDataBreachProbabilityRight := what[j].IdentifiedDataBreachProbabilityStillAtRisk()
	if highestDataBreachProbabilityLeft == highestDataBreachProbabilityRight {
		if len(risksLeft) == 0 && len(risksRight) > 0 {
			return false
		}
		if len(risksLeft) > 0 && len(risksRight) == 0 {
			return true
		}
		return what[i].Title < what[j].Title
	}
	return highestDataBreachProbabilityLeft > highestDataBreachProbabilityRight
}

type ByOrderAndIdSort []TechnicalAsset

func (what ByOrderAndIdSort) Len() int      { return len(what) }
func (what ByOrderAndIdSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByOrderAndIdSort) Less(i, j int) bool {
	if what[i].DiagramTweakOrder == what[j].DiagramTweakOrder {
		return what[i].Id > what[j].Id
	}
	return what[i].DiagramTweakOrder < what[j].DiagramTweakOrder
}

type ByTechnicalAssetRiskSeverityAndTitleSortStillAtRisk []TechnicalAsset

func (what ByTechnicalAssetRiskSeverityAndTitleSortStillAtRisk) Len() int { return len(what) }
func (what ByTechnicalAssetRiskSeverityAndTitleSortStillAtRisk) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByTechnicalAssetRiskSeverityAndTitleSortStillAtRisk) Less(i, j int) bool {
	risksLeft := ReduceToOnlyStillAtRisk(what[i].GeneratedRisks())
	risksRight := ReduceToOnlyStillAtRisk(what[j].GeneratedRisks())
	highestSeverityLeft := HighestSeverityStillAtRisk(risksLeft)
	highestSeverityRight := HighestSeverityStillAtRisk(risksRight)
	var result bool
	if highestSeverityLeft == highestSeverityRight {
		if len(risksLeft) == 0 && len(risksRight) > 0 {
			return false
		} else if len(risksLeft) > 0 && len(risksRight) == 0 {
			return true
		} else {
			result = what[i].Title < what[j].Title
		}
	} else {
		result = highestSeverityLeft > highestSeverityRight
	}
	if what[i].OutOfScope && what[j].OutOfScope {
		result = what[i].Title < what[j].Title
	} else if what[i].OutOfScope {
		result = false
	} else if what[j].OutOfScope {
		result = true
	}
	return result
}

type ByTechnicalAssetRAAAndTitleSort []TechnicalAsset

func (what ByTechnicalAssetRAAAndTitleSort) Len() int      { return len(what) }
func (what ByTechnicalAssetRAAAndTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalAssetRAAAndTitleSort) Less(i, j int) bool {
	raaLeft := what[i].RAA
	raaRight := what[j].RAA
	if raaLeft == raaRight {
		return what[i].Title < what[j].Title
	}
	return raaLeft > raaRight
}

/*
type ByTechnicalAssetQuickWinsAndTitleSort []TechnicalAsset

func (what ByTechnicalAssetQuickWinsAndTitleSort) Len() int      { return len(what) }
func (what ByTechnicalAssetQuickWinsAndTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalAssetQuickWinsAndTitleSort) Less(i, j int) bool {
	qwLeft := what[i].QuickWins()
	qwRight := what[j].QuickWins()
	if qwLeft == qwRight {
		return what[i].Title < what[j].Title
	}
	return qwLeft > qwRight
}
*/

type ByTechnicalAssetTitleSort []TechnicalAsset

func (what ByTechnicalAssetTitleSort) Len() int      { return len(what) }
func (what ByTechnicalAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type ByTrustBoundaryTitleSort []TrustBoundary

func (what ByTrustBoundaryTitleSort) Len() int      { return len(what) }
func (what ByTrustBoundaryTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTrustBoundaryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type BySharedRuntimeTitleSort []SharedRuntime

func (what BySharedRuntimeTitleSort) Len() int      { return len(what) }
func (what BySharedRuntimeTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what BySharedRuntimeTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type ByDataAssetTitleSort []DataAsset

func (what ByDataAssetTitleSort) Len() int      { return len(what) }
func (what ByDataAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type ByDataFormatAcceptedSort []DataFormat

func (what ByDataFormatAcceptedSort) Len() int      { return len(what) }
func (what ByDataFormatAcceptedSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataFormatAcceptedSort) Less(i, j int) bool {
	return what[i].String() < what[j].String()
}

type CommunicationLink struct {
	Id, SourceId, TargetId, Title, Description string
	Protocol                                   Protocol
	Tags                                       []string
	VPN, IpFiltered, Readonly                  bool
	Authentication                             Authentication
	Authorization                              Authorization
	Usage                                      Usage
	DataAssetsSent, DataAssetsReceived         []string
	DiagramTweakWeight                         int
	DiagramTweakConstraint                     bool
}

func (what CommunicationLink) IsTaggedWithAny(tags ...string) bool {
	return ContainsCaseInsensitiveAny(what.Tags, tags...)
}

func (what CommunicationLink) IsTaggedWithBaseTag(basetag string) bool {
	return IsTaggedWithBaseTag(what.Tags, basetag)
}

type ByTechnicalCommunicationLinkIdSort []CommunicationLink

func (what ByTechnicalCommunicationLinkIdSort) Len() int      { return len(what) }
func (what ByTechnicalCommunicationLinkIdSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalCommunicationLinkIdSort) Less(i, j int) bool {
	return what[i].Id > what[j].Id
}

type ByTechnicalCommunicationLinkTitleSort []CommunicationLink

func (what ByTechnicalCommunicationLinkTitleSort) Len() int      { return len(what) }
func (what ByTechnicalCommunicationLinkTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalCommunicationLinkTitleSort) Less(i, j int) bool {
	return what[i].Title > what[j].Title
}

type TrustBoundary struct {
	Id, Title, Description string
	Type                   TrustBoundaryType
	Tags                   []string
	TechnicalAssetsInside  []string
	TrustBoundariesNested  []string
}

func (what TrustBoundary) IsTaggedWithAny(tags ...string) bool {
	return ContainsCaseInsensitiveAny(what.Tags, tags...)
}

func (what TrustBoundary) IsTaggedWithBaseTag(basetag string) bool {
	return IsTaggedWithBaseTag(what.Tags, basetag)
}

func (what TrustBoundary) IsTaggedWithAnyTraversingUp(tags ...string) bool {
	if what.IsTaggedWithAny(tags...) {
		return true
	}
	parentID := what.ParentTrustBoundaryID()
	if len(parentID) > 0 && ParsedModelRoot.TrustBoundaries[parentID].IsTaggedWithAnyTraversingUp(tags...) {
		return true
	}
	return false
}

func (what TrustBoundary) ParentTrustBoundaryID() string {
	var result string
	for _, candidate := range ParsedModelRoot.TrustBoundaries {
		if Contains(candidate.TrustBoundariesNested, what.Id) {
			result = candidate.Id
			return result
		}
	}
	return result
}

func (what TrustBoundary) HighestConfidentiality() Confidentiality {
	highest := Public
	for _, id := range what.RecursivelyAllTechnicalAssetIDsInside() {
		techAsset := ParsedModelRoot.TechnicalAssets[id]
		if techAsset.HighestConfidentiality() > highest {
			highest = techAsset.HighestConfidentiality()
		}
	}
	return highest
}

func (what TrustBoundary) HighestIntegrity() Criticality {
	highest := Archive
	for _, id := range what.RecursivelyAllTechnicalAssetIDsInside() {
		techAsset := ParsedModelRoot.TechnicalAssets[id]
		if techAsset.HighestIntegrity() > highest {
			highest = techAsset.HighestIntegrity()
		}
	}
	return highest
}

func (what TrustBoundary) HighestAvailability() Criticality {
	highest := Archive
	for _, id := range what.RecursivelyAllTechnicalAssetIDsInside() {
		techAsset := ParsedModelRoot.TechnicalAssets[id]
		if techAsset.HighestAvailability() > highest {
			highest = techAsset.HighestAvailability()
		}
	}
	return highest
}

type SharedRuntime struct {
	Id, Title, Description string
	Tags                   []string
	TechnicalAssetsRunning []string
}

func (what SharedRuntime) IsTaggedWithAny(tags ...string) bool {
	return ContainsCaseInsensitiveAny(what.Tags, tags...)
}

func (what SharedRuntime) IsTaggedWithBaseTag(basetag string) bool {
	return IsTaggedWithBaseTag(what.Tags, basetag)
}

func (what SharedRuntime) HighestConfidentiality() Confidentiality {
	highest := Public
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := ParsedModelRoot.TechnicalAssets[id]
		if techAsset.HighestConfidentiality() > highest {
			highest = techAsset.HighestConfidentiality()
		}
	}
	return highest
}

func (what SharedRuntime) HighestIntegrity() Criticality {
	highest := Archive
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := ParsedModelRoot.TechnicalAssets[id]
		if techAsset.HighestIntegrity() > highest {
			highest = techAsset.HighestIntegrity()
		}
	}
	return highest
}

func (what SharedRuntime) HighestAvailability() Criticality {
	highest := Archive
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := ParsedModelRoot.TechnicalAssets[id]
		if techAsset.HighestAvailability() > highest {
			highest = techAsset.HighestAvailability()
		}
	}
	return highest
}

func (what SharedRuntime) TechnicalAssetWithHighestRAA() TechnicalAsset {
	result := ParsedModelRoot.TechnicalAssets[what.TechnicalAssetsRunning[0]]
	for _, asset := range what.TechnicalAssetsRunning {
		candidate := ParsedModelRoot.TechnicalAssets[asset]
		if candidate.RAA > result.RAA {
			result = candidate
		}
	}
	return result
}

func (what CommunicationLink) IsAcrossTrustBoundary() bool {
	trustBoundaryOfSourceAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.SourceId]
	trustBoundaryOfTargetAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.TargetId]
	return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id
}

func (what CommunicationLink) IsAcrossTrustBoundaryNetworkOnly() bool {
	trustBoundaryOfSourceAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.SourceId]
	if !trustBoundaryOfSourceAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfSourceAsset = ParsedModelRoot.TrustBoundaries[trustBoundaryOfSourceAsset.ParentTrustBoundaryID()]
	}
	trustBoundaryOfTargetAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.TargetId]
	if !trustBoundaryOfTargetAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfTargetAsset = ParsedModelRoot.TrustBoundaries[trustBoundaryOfTargetAsset.ParentTrustBoundaryID()]
	}
	return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id && trustBoundaryOfTargetAsset.Type.IsNetworkBoundary()
}

func (what CommunicationLink) HighestConfidentiality() Confidentiality {
	highest := Public
	for _, dataId := range what.DataAssetsSent {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	return highest
}

func (what CommunicationLink) HighestIntegrity() Criticality {
	highest := Archive
	for _, dataId := range what.DataAssetsSent {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	return highest
}

func (what CommunicationLink) HighestAvailability() Criticality {
	highest := Archive
	for _, dataId := range what.DataAssetsSent {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	return highest
}

func (what CommunicationLink) DataAssetsSentSorted() []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsSent {
		result = append(result, ParsedModelRoot.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (what CommunicationLink) DataAssetsReceivedSorted() []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsReceived {
		result = append(result, ParsedModelRoot.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

type Author struct {
	Name     string `json:"name"`
	Homepage string `json:"homepage"`
}

type Overview struct {
	Description string              `json:"description"`
	Images      []map[string]string `json:"images"` // yes, array of map here, as array keeps the order of the image keys
}

type ParsedModel struct {
	Author                                        Author
	Title                                         string
	Date                                          time.Time
	ManagementSummaryComment                      string
	BusinessOverview                              Overview
	TechnicalOverview                             Overview
	BusinessCriticality                           Criticality
	SecurityRequirements                          map[string]string
	Questions                                     map[string]string
	AbuseCases                                    map[string]string
	TagsAvailable                                 []string
	DataAssets                                    map[string]DataAsset
	TechnicalAssets                               map[string]TechnicalAsset
	TrustBoundaries                               map[string]TrustBoundary
	SharedRuntimes                                map[string]SharedRuntime
	IndividualRiskCategories                      map[string]RiskCategory
	RiskTracking                                  map[string]RiskTracking
	DiagramTweakNodesep, DiagramTweakRanksep      int
	DiagramTweakEdgeLayout                        string
	DiagramTweakSuppressEdgeLabels                bool
	DiagramTweakLayoutLeftToRight                 bool
	DiagramTweakInvisibleConnectionsBetweenAssets []string
	DiagramTweakSameRankAssets                    []string
}

func SortedTechnicalAssetIDs() []string {
	res := make([]string, 0)
	for id, _ := range ParsedModelRoot.TechnicalAssets {
		res = append(res, id)
	}
	sort.Strings(res)
	return res
}

func TagsActuallyUsed() []string {
	result := make([]string, 0)
	for _, tag := range ParsedModelRoot.TagsAvailable {
		if len(TechnicalAssetsTaggedWithAny(tag)) > 0 ||
			len(CommunicationLinksTaggedWithAny(tag)) > 0 ||
			len(DataAssetsTaggedWithAny(tag)) > 0 ||
			len(TrustBoundariesTaggedWithAny(tag)) > 0 ||
			len(SharedRuntimesTaggedWithAny(tag)) > 0 {
			result = append(result, tag)
		}
	}
	return result
}

// === Sorting stuff =====================================

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfIndividualRiskCategories() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.IndividualRiskCategories {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfSecurityRequirements() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.SecurityRequirements {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfAbuseCases() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.AbuseCases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfQuestions() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.Questions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfDataAssets() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.DataAssets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfTechnicalAssets() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.TechnicalAssets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TechnicalAssetsTaggedWithAny(tags ...string) []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, candidate := range ParsedModelRoot.TechnicalAssets {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func CommunicationLinksTaggedWithAny(tags ...string) []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, asset := range ParsedModelRoot.TechnicalAssets {
		for _, candidate := range asset.CommunicationLinks {
			if candidate.IsTaggedWithAny(tags...) {
				result = append(result, candidate)
			}
		}
	}
	return result
}

func DataAssetsTaggedWithAny(tags ...string) []DataAsset {
	result := make([]DataAsset, 0)
	for _, candidate := range ParsedModelRoot.DataAssets {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func TrustBoundariesTaggedWithAny(tags ...string) []TrustBoundary {
	result := make([]TrustBoundary, 0)
	for _, candidate := range ParsedModelRoot.TrustBoundaries {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func SharedRuntimesTaggedWithAny(tags ...string) []SharedRuntime {
	result := make([]SharedRuntime, 0)
	for _, candidate := range ParsedModelRoot.SharedRuntimes {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedTechnicalAssetsByTitle() []TechnicalAsset {
	assets := make([]TechnicalAsset, 0)
	for _, asset := range ParsedModelRoot.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(ByTechnicalAssetTitleSort(assets))
	return assets
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedDataAssetsByTitle() []DataAsset {
	assets := make([]DataAsset, 0)
	for _, asset := range ParsedModelRoot.DataAssets {
		assets = append(assets, asset)
	}
	sort.Sort(ByDataAssetTitleSort(assets))
	return assets
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedDataAssetsByDataBreachProbabilityAndTitleStillAtRisk() []DataAsset {
	assets := make([]DataAsset, 0)
	for _, asset := range ParsedModelRoot.DataAssets {
		assets = append(assets, asset)
	}
	sort.Sort(ByDataAssetDataBreachProbabilityAndTitleSortStillAtRisk(assets))
	return assets
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedDataAssetsByDataBreachProbabilityAndTitle() []DataAsset {
	assets := make([]DataAsset, 0)
	for _, asset := range ParsedModelRoot.DataAssets {
		assets = append(assets, asset)
	}
	sort.Sort(ByDataAssetDataBreachProbabilityAndTitleSortStillAtRisk(assets))
	return assets
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedTechnicalAssetsByRiskSeverityAndTitle() []TechnicalAsset {
	assets := make([]TechnicalAsset, 0)
	for _, asset := range ParsedModelRoot.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(ByTechnicalAssetRiskSeverityAndTitleSortStillAtRisk(assets))
	return assets
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedTechnicalAssetsByRAAAndTitle() []TechnicalAsset {
	assets := make([]TechnicalAsset, 0)
	for _, asset := range ParsedModelRoot.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(ByTechnicalAssetRAAAndTitleSort(assets))
	return assets
}

/*
// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedTechnicalAssetsByQuickWinsAndTitle() []TechnicalAsset {
	assets := make([]TechnicalAsset, 0)
	for _, asset := range ParsedModelRoot.TechnicalAssets {
		if !asset.OutOfScope && asset.QuickWins() > 0 {
			assets = append(assets, asset)
		}
	}
	sort.Sort(ByTechnicalAssetQuickWinsAndTitleSort(assets))
	return assets
}
*/

func OutOfScopeTechnicalAssets() []TechnicalAsset {
	assets := make([]TechnicalAsset, 0)
	for _, asset := range ParsedModelRoot.TechnicalAssets {
		if asset.OutOfScope {
			assets = append(assets, asset)
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(assets))
	return assets
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfTrustBoundaries() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func SortedTrustBoundariesByTitle() []TrustBoundary {
	boundaries := make([]TrustBoundary, 0)
	for _, boundary := range ParsedModelRoot.TrustBoundaries {
		boundaries = append(boundaries, boundary)
	}
	sort.Sort(ByTrustBoundaryTitleSort(boundaries))
	return boundaries
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfSharedRuntime() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.SharedRuntimes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func SortedSharedRuntimesByTitle() []SharedRuntime {
	result := make([]SharedRuntime, 0)
	for _, runtime := range ParsedModelRoot.SharedRuntimes {
		result = append(result, runtime)
	}
	sort.Sort(BySharedRuntimeTitleSort(result))
	return result
}

func QuestionsUnanswered() int {
	result := 0
	for _, answer := range ParsedModelRoot.Questions {
		if len(strings.TrimSpace(answer)) == 0 {
			result++
		}
	}
	return result
}

// === Style stuff =======================================

// Line Styles:

// dotted when model forgery attempt (i.e. nothing being sent and received)
func (what CommunicationLink) DetermineArrowLineStyle() string {
	if len(what.DataAssetsSent) == 0 && len(what.DataAssetsReceived) == 0 {
		return "dotted" // dotted, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	if what.Usage == DevOps {
		return "dashed"
	}
	return "solid"
}

// dotted when model forgery attempt (i.e. nothing being processed or stored)
func (what TechnicalAsset) DetermineShapeBorderLineStyle() string {
	if len(what.DataAssetsProcessed) == 0 && len(what.DataAssetsStored) == 0 || what.OutOfScope {
		return "dotted" // dotted, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	return "solid"
}

// 3 when redundant
func (what TechnicalAsset) DetermineShapePeripheries() int {
	if what.Redundant {
		return 2
	}
	return 1
}

func (what TechnicalAsset) DetermineShapeStyle() string {
	return "filled"
}

func (what TechnicalAsset) GetTrustBoundaryId() string {
	for _, trustBoundary := range ParsedModelRoot.TrustBoundaries {
		for _, techAssetInside := range trustBoundary.TechnicalAssetsInside {
			if techAssetInside == what.Id {
				return trustBoundary.Id
			}
		}
	}
	return ""
}

// Pen Widths:

func (what CommunicationLink) DetermineArrowPenWidth() string {
	if what.DetermineArrowColor() == colors.Pink {
		return fmt.Sprintf("%f", 3.0)
	}
	if what.DetermineArrowColor() != colors.Black {
		return fmt.Sprintf("%f", 2.5)
	}
	return fmt.Sprintf("%f", 1.5)
}

func (what TechnicalAsset) DetermineShapeBorderPenWidth() string {
	if what.DetermineShapeBorderColor() == colors.Pink {
		return fmt.Sprintf("%f", 3.5)
	}
	if what.DetermineShapeBorderColor() != colors.Black {
		return fmt.Sprintf("%f", 3.0)
	}
	return fmt.Sprintf("%f", 2.0)
}

/*
// Loops over all data assets (stored and processed by this technical asset) and determines for each
// data asset, how many percentage of the data risk is reduced when this technical asset has all risks mitigated.
// Example: This means if the data asset is loosing a risk and thus getting from red to amber it counts as 1.
// Other example: When only one out of four lines (see data risk mapping) leading to red tech assets are removed by
// the mitigations, then this counts as 0.25. The overall sum is returned.
func (what TechnicalAsset) QuickWins() float64 {
	result := 0.0
	uniqueDataAssetsStoredAndProcessed := make(map[string]interface{})
	for _, dataAssetId := range what.DataAssetsStored {
		uniqueDataAssetsStoredAndProcessed[dataAssetId] = true
	}
	for _, dataAssetId := range what.DataAssetsProcessed {
		uniqueDataAssetsStoredAndProcessed[dataAssetId] = true
	}
	highestSeverity := HighestSeverityStillAtRisk(what.GeneratedRisks())
	for dataAssetId, _ := range uniqueDataAssetsStoredAndProcessed {
		dataAsset := ParsedModelRoot.DataAssets[dataAssetId]
		if dataAsset.IdentifiedRiskSeverityStillAtRisk() <= highestSeverity {
			howManySameLevelCausingUsagesOfThisData := 0.0
			for techAssetId, risks := range dataAsset.IdentifiedRisksByResponsibleTechnicalAssetId() {
				if !ParsedModelRoot.TechnicalAssets[techAssetId].OutOfScope {
					for _, risk := range risks {
						if len(risk.MostRelevantTechnicalAssetId) > 0 { // T O D O caching of generated risks inside the method?
							if HighestSeverityStillAtRisk(ParsedModelRoot.TechnicalAssets[risk.MostRelevantTechnicalAssetId].GeneratedRisks()) == highestSeverity {
								howManySameLevelCausingUsagesOfThisData++
								break
							}
						}
					}
				}
			}
			if howManySameLevelCausingUsagesOfThisData > 0 {
				result += 1.0 / howManySameLevelCausingUsagesOfThisData
			}
		}
	}
	return result
}
*/

func (what CommunicationLink) IsBidirectional() bool {
	return len(what.DataAssetsSent) > 0 && len(what.DataAssetsReceived) > 0
}

// Contains tells whether a contains x (in an unsorted slice)
func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func ContainsCaseInsensitiveAny(a []string, x ...string) bool {
	for _, n := range a {
		for _, c := range x {
			if strings.TrimSpace(strings.ToLower(c)) == strings.TrimSpace(strings.ToLower(n)) {
				return true
			}
		}
	}
	return false
}

func (what TechnicalAsset) IsZero() bool {
	return len(what.Id) == 0
}

func (what TechnicalAsset) ProcessesOrStoresDataAsset(dataAssetId string) bool {
	if Contains(what.DataAssetsProcessed, dataAssetId) {
		return true
	}
	if Contains(what.DataAssetsStored, dataAssetId) {
		return true
	}
	return false
}

// red when >= confidential data stored in unencrypted technical asset
func (what TechnicalAsset) DetermineLabelColor() string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	// Check for red
	if what.Integrity == MissionCritical {
		return colors.Red
	}
	for _, storedDataAsset := range what.DataAssetsStored {
		if ParsedModelRoot.DataAssets[storedDataAsset].Integrity == MissionCritical {
			return colors.Red
		}
	}
	for _, processedDataAsset := range what.DataAssetsProcessed {
		if ParsedModelRoot.DataAssets[processedDataAsset].Integrity == MissionCritical {
			return colors.Red
		}
	}
	// Check for amber
	if what.Integrity == Critical {
		return colors.Amber
	}
	for _, storedDataAsset := range what.DataAssetsStored {
		if ParsedModelRoot.DataAssets[storedDataAsset].Integrity == Critical {
			return colors.Amber
		}
	}
	for _, processedDataAsset := range what.DataAssetsProcessed {
		if ParsedModelRoot.DataAssets[processedDataAsset].Integrity == Critical {
			return colors.Amber
		}
	}
	return colors.Black
	/*
		if what.Encrypted {
			return colors.Black
		} else {
			if what.Confidentiality == StrictlyConfidential {
				return colors.Red
			}
			for _, storedDataAsset := range what.DataAssetsStored {
				if ParsedModelRoot.DataAssets[storedDataAsset].Confidentiality == StrictlyConfidential {
					return colors.Red
				}
			}
			if what.Confidentiality == Confidential {
				return colors.Amber
			}
			for _, storedDataAsset := range what.DataAssetsStored {
				if ParsedModelRoot.DataAssets[storedDataAsset].Confidentiality == Confidential {
					return colors.Amber
				}
			}
			return colors.Black
		}
	*/
}

// red when mission-critical integrity, but still unauthenticated (non-readonly) channels access it
// amber when critical integrity, but still unauthenticated (non-readonly) channels access it
// pink when model forgery attempt (i.e. nothing being processed or stored)
func (what TechnicalAsset) DetermineShapeBorderColor() string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	// Check for red
	if what.Confidentiality == StrictlyConfidential {
		return colors.Red
	}
	for _, storedDataAsset := range what.DataAssetsStored {
		if ParsedModelRoot.DataAssets[storedDataAsset].Confidentiality == StrictlyConfidential {
			return colors.Red
		}
	}
	for _, processedDataAsset := range what.DataAssetsProcessed {
		if ParsedModelRoot.DataAssets[processedDataAsset].Confidentiality == StrictlyConfidential {
			return colors.Red
		}
	}
	// Check for amber
	if what.Confidentiality == Confidential {
		return colors.Amber
	}
	for _, storedDataAsset := range what.DataAssetsStored {
		if ParsedModelRoot.DataAssets[storedDataAsset].Confidentiality == Confidential {
			return colors.Amber
		}
	}
	for _, processedDataAsset := range what.DataAssetsProcessed {
		if ParsedModelRoot.DataAssets[processedDataAsset].Confidentiality == Confidential {
			return colors.Amber
		}
	}
	return colors.Black
	/*
		if what.Integrity == MissionCritical {
			for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
				if !dataFlow.Readonly && dataFlow.Authentication == NoneAuthentication {
					return colors.Red
				}
			}
		}

		if what.Integrity == Critical {
			for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
				if !dataFlow.Readonly && dataFlow.Authentication == NoneAuthentication {
					return colors.Amber
				}
			}
		}

		if len(what.DataAssetsProcessed) == 0 && len(what.DataAssetsStored) == 0 {
			return colors.Pink // pink, because it's strange when too many technical assets process no data... some ok, but many in a diagram ist a sign of model forgery...
		}

		return colors.Black
	*/
}

func (what CommunicationLink) DetermineLabelColor() string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	/*
		if dataFlow.Protocol.IsEncrypted() {
			return colors.Gray
		} else {*/
	// check for red
	for _, sentDataAsset := range what.DataAssetsSent {
		if ParsedModelRoot.DataAssets[sentDataAsset].Integrity == MissionCritical {
			return colors.Red
		}
	}
	for _, receivedDataAsset := range what.DataAssetsReceived {
		if ParsedModelRoot.DataAssets[receivedDataAsset].Integrity == MissionCritical {
			return colors.Red
		}
	}
	// check for amber
	for _, sentDataAsset := range what.DataAssetsSent {
		if ParsedModelRoot.DataAssets[sentDataAsset].Integrity == Critical {
			return colors.Amber
		}
	}
	for _, receivedDataAsset := range what.DataAssetsReceived {
		if ParsedModelRoot.DataAssets[receivedDataAsset].Integrity == Critical {
			return colors.Amber
		}
	}
	// default
	return colors.Gray

}

// pink when model forgery attempt (i.e. nothing being sent and received)
func (what CommunicationLink) DetermineArrowColor() string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	if len(what.DataAssetsSent) == 0 && len(what.DataAssetsReceived) == 0 ||
		what.Protocol == UnknownProtocol {
		return colors.Pink // pink, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	if what.Usage == DevOps {
		return colors.MiddleLightGray
	} else if what.VPN {
		return colors.DarkBlue
	} else if what.IpFiltered {
		return colors.Brown
	}
	// check for red
	for _, sentDataAsset := range what.DataAssetsSent {
		if ParsedModelRoot.DataAssets[sentDataAsset].Confidentiality == StrictlyConfidential {
			return colors.Red
		}
	}
	for _, receivedDataAsset := range what.DataAssetsReceived {
		if ParsedModelRoot.DataAssets[receivedDataAsset].Confidentiality == StrictlyConfidential {
			return colors.Red
		}
	}
	// check for amber
	for _, sentDataAsset := range what.DataAssetsSent {
		if ParsedModelRoot.DataAssets[sentDataAsset].Confidentiality == Confidential {
			return colors.Amber
		}
	}
	for _, receivedDataAsset := range what.DataAssetsReceived {
		if ParsedModelRoot.DataAssets[receivedDataAsset].Confidentiality == Confidential {
			return colors.Amber
		}
	}
	// default
	return colors.Black
	/*
		} else if dataFlow.Authentication != NoneAuthentication {
			return colors.Black
		} else {
			// check for red
			for _, sentDataAsset := range dataFlow.DataAssetsSent { // first check if any red?
				if ParsedModelRoot.DataAssets[sentDataAsset].Integrity == MissionCritical {
					return colors.Red
				}
			}
			for _, receivedDataAsset := range dataFlow.DataAssetsReceived { // first check if any red?
				if ParsedModelRoot.DataAssets[receivedDataAsset].Integrity == MissionCritical {
					return colors.Red
				}
			}
			// check for amber
			for _, sentDataAsset := range dataFlow.DataAssetsSent { // then check if any amber?
				if ParsedModelRoot.DataAssets[sentDataAsset].Integrity == Critical {
					return colors.Amber
				}
			}
			for _, receivedDataAsset := range dataFlow.DataAssetsReceived { // then check if any amber?
				if ParsedModelRoot.DataAssets[receivedDataAsset].Integrity == Critical {
					return colors.Amber
				}
			}
			return colors.Black
		}
	*/
}

func (what TechnicalAsset) DetermineShapeFillColor() string {
	fillColor := colors.VeryLightGray
	if len(what.DataAssetsProcessed) == 0 && len(what.DataAssetsStored) == 0 ||
		what.Technology == UnknownTechnology {
		fillColor = colors.LightPink // lightPink, because it's strange when too many technical assets process no data... some ok, but many in a diagram ist a sign of model forgery...
	} else if len(what.CommunicationLinks) == 0 && len(IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id]) == 0 {
		fillColor = colors.LightPink
	} else if what.Internet {
		fillColor = colors.ExtremeLightBlue
	} else if what.OutOfScope {
		fillColor = colors.OutOfScopeFancy
	} else if what.CustomDevelopedParts {
		fillColor = colors.CustomDevelopedParts
	}
	switch what.Machine {
	case Physical:
		fillColor = colors.DarkenHexColor(fillColor)
	case Container:
		fillColor = colors.BrightenHexColor(fillColor)
	case Serverless:
		fillColor = colors.BrightenHexColor(colors.BrightenHexColor(fillColor))
	}
	return fillColor
}

// === Risk stuff ========================================

type DataBreachProbability int

const (
	Improbable DataBreachProbability = iota
	Possible
	Probable
)

func DataBreachProbabilityValues() []TypeEnum {
	return []TypeEnum{
		Improbable,
		Possible,
		Probable,
	}
}

func (what DataBreachProbability) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"improbable", "possible", "probable"}[what]
}

func (what DataBreachProbability) Title() string {
	return [...]string{"Improbable", "Possible", "Probable"}[what]
}

func (what DataBreachProbability) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func CalculateSeverity(likelihood RiskExploitationLikelihood, impact RiskExploitationImpact) RiskSeverity {
	result := likelihood.Weight() * impact.Weight()
	if result <= 1 {
		return LowSeverity
	}
	if result <= 3 {
		return MediumSeverity
	}
	if result <= 8 {
		return ElevatedSeverity
	}
	if result <= 12 {
		return HighSeverity
	}
	return CriticalSeverity
}

type RiskSeverity int

const (
	LowSeverity RiskSeverity = iota
	MediumSeverity
	ElevatedSeverity
	HighSeverity
	CriticalSeverity
)

func RiskSeverityValues() []TypeEnum {
	return []TypeEnum{
		LowSeverity,
		MediumSeverity,
		ElevatedSeverity,
		HighSeverity,
		CriticalSeverity,
	}
}

func (what RiskSeverity) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"low", "medium", "elevated", "high", "critical"}[what]
}

func (what RiskSeverity) Title() string {
	return [...]string{"Low", "Medium", "Elevated", "High", "Critical"}[what]
}

func (what RiskSeverity) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

type RiskExploitationLikelihood int

const (
	Unlikely RiskExploitationLikelihood = iota
	Likely
	VeryLikely
	Frequent
)

func RiskExploitationLikelihoodValues() []TypeEnum {
	return []TypeEnum{
		Unlikely,
		Likely,
		VeryLikely,
		Frequent,
	}
}

func (what RiskExploitationLikelihood) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unlikely", "likely", "very-likely", "frequent"}[what]
}

func (what RiskExploitationLikelihood) Title() string {
	return [...]string{"Unlikely", "Likely", "Very Likely", "Frequent"}[what]
}

func (what RiskExploitationLikelihood) Weight() int {
	return [...]int{1, 2, 3, 4}[what]
}

func (what RiskExploitationLikelihood) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

type RiskExploitationImpact int

const (
	LowImpact RiskExploitationImpact = iota
	MediumImpact
	HighImpact
	VeryHighImpact
)

func RiskExploitationImpactValues() []TypeEnum {
	return []TypeEnum{
		LowImpact,
		MediumImpact,
		HighImpact,
		VeryHighImpact,
	}
}

func (what RiskExploitationImpact) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"low", "medium", "high", "very-high"}[what]
}

func (what RiskExploitationImpact) Title() string {
	return [...]string{"Low", "Medium", "High", "Very High"}[what]
}

func (what RiskExploitationImpact) Weight() int {
	return [...]int{1, 2, 3, 4}[what]
}

func (what RiskExploitationImpact) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

type RiskFunction int

const (
	BusinessSide RiskFunction = iota
	Architecture
	Development
	Operations
)

func RiskFunctionValues() []TypeEnum {
	return []TypeEnum{
		BusinessSide,
		Architecture,
		Development,
		Operations,
	}
}

func (what RiskFunction) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"business-side", "architecture", "development", "operations"}[what]
}

func (what RiskFunction) Title() string {
	return [...]string{"Business Side", "Architecture", "Development", "Operations"}[what]
}

func (what RiskFunction) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

type STRIDE int

const (
	Spoofing STRIDE = iota
	Tampering
	Repudiation
	InformationDisclosure
	DenialOfService
	ElevationOfPrivilege
)

func STRIDEValues() []TypeEnum {
	return []TypeEnum{
		Spoofing,
		Tampering,
		Repudiation,
		InformationDisclosure,
		DenialOfService,
		ElevationOfPrivilege,
	}
}

func (what STRIDE) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"spoofing", "tampering", "repudiation", "information-disclosure", "denial-of-service", "elevation-of-privilege"}[what]
}

func (what STRIDE) Title() string {
	return [...]string{"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}[what]
}

func (what STRIDE) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

type MacroDetails struct {
	ID, Title, Description string
}

type MacroQuestion struct {
	ID, Title, Description string
	PossibleAnswers        []string
	MultiSelect            bool
	DefaultAnswer          string
}

const NoMoreQuestionsID = ""

func NoMoreQuestions() MacroQuestion {
	return MacroQuestion{
		ID:              NoMoreQuestionsID,
		Title:           "",
		Description:     "",
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "",
	}
}

func (what MacroQuestion) NoMoreQuestions() bool {
	return what.ID == NoMoreQuestionsID
}

func (what MacroQuestion) IsValueConstrained() bool {
	return what.PossibleAnswers != nil && len(what.PossibleAnswers) > 0
}

func (what MacroQuestion) IsMatchingValueConstraint(answer string) bool {
	if what.IsValueConstrained() {
		for _, val := range what.PossibleAnswers {
			if strings.ToLower(val) == strings.ToLower(answer) {
				return true
			}
		}
		return false
	}
	return true
}

type RiskCategory struct {
	// TODO: refactor all "Id" here and elsewhere to "ID"
	Id                         string
	Title                      string
	Description                string
	Impact                     string
	ASVS                       string
	CheatSheet                 string
	Action                     string
	Mitigation                 string
	Check                      string
	DetectionLogic             string
	RiskAssessment             string
	FalsePositives             string
	Function                   RiskFunction
	STRIDE                     STRIDE
	ModelFailurePossibleReason bool
	CWE                        int
}

type ByRiskCategoryTitleSort []RiskCategory

func (what ByRiskCategoryTitleSort) Len() int { return len(what) }
func (what ByRiskCategoryTitleSort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByRiskCategoryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk []RiskCategory

func (what ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk) Len() int { return len(what) }
func (what ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk) Less(i, j int) bool {
	risksLeft := ReduceToOnlyStillAtRisk(GeneratedRisksByCategory[what[i]])
	risksRight := ReduceToOnlyStillAtRisk(GeneratedRisksByCategory[what[j]])
	highestLeft := HighestSeverityStillAtRisk(risksLeft)
	highestRight := HighestSeverityStillAtRisk(risksRight)
	if highestLeft == highestRight {
		if len(risksLeft) == 0 && len(risksRight) > 0 {
			return false
		}
		if len(risksLeft) > 0 && len(risksRight) == 0 {
			return true
		}
		return what[i].Title < what[j].Title
	}
	return highestLeft > highestRight
}

type RiskStatistics struct {
	// TODO add also some more like before / after (i.e. with mitigation applied)
	Risks map[string]map[string]int `json:"risks"`
}

type Risk struct {
	Category                        RiskCategory               `json:"-"`           // just for navigational convenience... not JSON marshalled
	CategoryId                      string                     `json:"category"`    // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	RiskStatus                      RiskStatus                 `json:"risk_status"` // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	Severity                        RiskSeverity               `json:"severity"`
	ExploitationLikelihood          RiskExploitationLikelihood `json:"exploitation_likelihood"`
	ExploitationImpact              RiskExploitationImpact     `json:"exploitation_impact"`
	Title                           string                     `json:"title"`
	SyntheticId                     string                     `json:"synthetic_id"`
	MostRelevantDataAssetId         string                     `json:"most_relevant_data_asset"`
	MostRelevantTechnicalAssetId    string                     `json:"most_relevant_technical_asset"`
	MostRelevantTrustBoundaryId     string                     `json:"most_relevant_trust_boundary"`
	MostRelevantSharedRuntimeId     string                     `json:"most_relevant_shared_runtime"`
	MostRelevantCommunicationLinkId string                     `json:"most_relevant_communication_link"`
	DataBreachProbability           DataBreachProbability      `json:"data_breach_probability"`
	DataBreachTechnicalAssetIDs     []string                   `json:"data_breach_technical_assets"`
	// TODO: refactor all "Id" here to "ID"?
}

func (what Risk) GetRiskTracking() RiskTracking { // TODO: Unify function naming reagrding Get etc.
	var result RiskTracking
	if riskTracking, ok := ParsedModelRoot.RiskTracking[what.SyntheticId]; ok {
		result = riskTracking
	}
	return result
}

func (what Risk) GetRiskTrackingStatusDefaultingUnchecked() RiskStatus {
	if riskTracking, ok := ParsedModelRoot.RiskTracking[what.SyntheticId]; ok {
		return riskTracking.Status
	}
	return Unchecked
}

func (what Risk) IsRiskTracked() bool {
	if _, ok := ParsedModelRoot.RiskTracking[what.SyntheticId]; ok {
		return true
	}
	return false
}

type ByRiskSeveritySort []Risk

func (what ByRiskSeveritySort) Len() int { return len(what) }
func (what ByRiskSeveritySort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByRiskSeveritySort) Less(i, j int) bool {
	if what[i].Severity == what[j].Severity {
		trackingStatusLeft := what[i].GetRiskTrackingStatusDefaultingUnchecked()
		trackingStatusRight := what[j].GetRiskTrackingStatusDefaultingUnchecked()
		if trackingStatusLeft == trackingStatusRight {
			impactLeft := what[i].ExploitationImpact
			impactRight := what[j].ExploitationImpact
			if impactLeft == impactRight {
				likelihoodLeft := what[i].ExploitationLikelihood
				likelihoodRight := what[j].ExploitationLikelihood
				if likelihoodLeft == likelihoodRight {
					return what[i].Title < what[j].Title
				} else {
					return likelihoodLeft > likelihoodRight
				}
			} else {
				return impactLeft > impactRight
			}
		} else {
			return trackingStatusLeft < trackingStatusRight
		}
	}
	return what[i].Severity > what[j].Severity
}

type ByDataBreachProbabilitySort []Risk

func (what ByDataBreachProbabilitySort) Len() int { return len(what) }
func (what ByDataBreachProbabilitySort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByDataBreachProbabilitySort) Less(i, j int) bool {
	if what[i].DataBreachProbability == what[j].DataBreachProbability {
		trackingStatusLeft := what[i].GetRiskTrackingStatusDefaultingUnchecked()
		trackingStatusRight := what[j].GetRiskTrackingStatusDefaultingUnchecked()
		if trackingStatusLeft == trackingStatusRight {
			return what[i].Title < what[j].Title
		} else {
			return trackingStatusLeft < trackingStatusRight
		}
	}
	return what[i].DataBreachProbability > what[j].DataBreachProbability
}

type RiskTracking struct {
	SyntheticRiskId, Justification, Ticket, CheckedBy string
	Status                                            RiskStatus
	Date                                              time.Time
}

type RiskStatus int

const (
	Unchecked RiskStatus = iota
	InDiscussion
	Accepted
	InProgress
	Mitigated
	FalsePositive
)

func RiskStatusValues() []TypeEnum {
	return []TypeEnum{
		Unchecked,
		InDiscussion,
		Accepted,
		InProgress,
		Mitigated,
		FalsePositive,
	}
}

func (what RiskStatus) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unchecked", "in-discussion", "accepted", "in-progress", "mitigated", "false-positive"}[what]
}

func (what RiskStatus) Title() string {
	return [...]string{"Unchecked", "in Discussion", "Accepted", "in Progress", "Mitigated", "False Positive"}[what]
}

func (what RiskStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what RiskStatus) IsStillAtRisk() bool {
	return what == Unchecked || what == InDiscussion || what == Accepted || what == InProgress
}

type RiskRule interface {
	Category() RiskCategory
	GenerateRisks(parsedModel ParsedModel) []Risk
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedRiskCategories() []RiskCategory {
	categories := make([]RiskCategory, 0)
	for k, _ := range GeneratedRisksByCategory {
		categories = append(categories, k)
	}
	sort.Sort(ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk(categories))
	return categories
}
func SortedRisksOfCategory(category RiskCategory) []Risk {
	risks := GeneratedRisksByCategory[category]
	sort.Sort(ByRiskSeveritySort(risks))
	return risks
}

func CountRisks(risksByCategory map[RiskCategory][]Risk) int {
	result := 0
	for _, risks := range risksByCategory {
		result += len(risks)
	}
	return result
}

func RisksOfOnlySTRIDESpoofing(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == Spoofing {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDETampering(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == Tampering {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDERepudiation(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == Repudiation {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEInformationDisclosure(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == InformationDisclosure {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEDenialOfService(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == DenialOfService {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEElevationOfPrivilege(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == ElevationOfPrivilege {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyBusinessSide(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == BusinessSide {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyArchitecture(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Architecture {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyDevelopment(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Development {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyOperation(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Operations {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func CategoriesOfOnlyRisksStillAtRisk(risksByCategory map[RiskCategory][]Risk) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			categories[risk.Category] = struct{}{}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyCriticalRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			if risk.Severity == CriticalSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyHighRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(GeneratedRisksByCategory[risk.Category])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(GeneratedRisksByCategory[risk.Category])
			}
			if risk.Severity == HighSeverity && highest < CriticalSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyElevatedRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(GeneratedRisksByCategory[risk.Category])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(GeneratedRisksByCategory[risk.Category])
			}
			if risk.Severity == ElevatedSeverity && highest < HighSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyMediumRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(GeneratedRisksByCategory[risk.Category])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(GeneratedRisksByCategory[risk.Category])
			}
			if risk.Severity == MediumSeverity && highest < ElevatedSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyLowRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(GeneratedRisksByCategory[risk.Category])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(GeneratedRisksByCategory[risk.Category])
			}
			if risk.Severity == LowSeverity && highest < MediumSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func HighestSeverity(risks []Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result {
			result = risk.Severity
		}
	}
	return result
}

func HighestSeverityStillAtRisk(risks []Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result && risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
			result = risk.Severity
		}
	}
	return result
}

func keysAsSlice(categories map[RiskCategory]struct{}) []RiskCategory {
	result := make([]RiskCategory, 0, len(categories))
	for k := range categories {
		result = append(result, k)
	}
	return result
}

func FilteredByOnlyBusinessSide() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == BusinessSide {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyArchitecture() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Architecture {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyDevelopment() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Development {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyOperation() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Operations {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyCriticalRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == CriticalSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyHighRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == HighSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyElevatedRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == ElevatedSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyMediumRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == MediumSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyLowRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == LowSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilterByModelFailures(risksByCat map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk, 0)
	for riskCat, risks := range risksByCat {
		if riskCat.ModelFailurePossibleReason {
			result[riskCat] = risks
		}
	}
	return result
}

func FlattenRiskSlice(risksByCat map[RiskCategory][]Risk) []Risk {
	result := make([]Risk, 0)
	for _, risks := range risksByCat {
		result = append(result, risks...)
	}
	return result
}

func TotalRiskCount() int {
	count := 0
	for _, risks := range GeneratedRisksByCategory {
		count += len(risks)
	}
	return count
}

func FilteredByRiskTrackingUnchecked() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == Unchecked {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingInDiscussion() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == InDiscussion {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingAccepted() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == Accepted {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingInProgress() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == InProgress {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingMitigated() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == Mitigated {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingFalsePositive() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == FalsePositive {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func ReduceToOnlyHighRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == HighSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyMediumRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == MediumSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyLowRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == LowSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingUnchecked(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == Unchecked {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingInDiscussion(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == InDiscussion {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingAccepted(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == Accepted {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingInProgress(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == InProgress {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingMitigated(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == Mitigated {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingFalsePositive(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == FalsePositive {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func FilteredByStillAtRisk() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func OverallRiskStatistics() RiskStatistics {
	result := RiskStatistics{}
	result.Risks = make(map[string]map[string]int)
	result.Risks[CriticalSeverity.String()] = make(map[string]int)
	result.Risks[CriticalSeverity.String()][Unchecked.String()] = 0
	result.Risks[CriticalSeverity.String()][InDiscussion.String()] = 0
	result.Risks[CriticalSeverity.String()][Accepted.String()] = 0
	result.Risks[CriticalSeverity.String()][InProgress.String()] = 0
	result.Risks[CriticalSeverity.String()][Mitigated.String()] = 0
	result.Risks[CriticalSeverity.String()][FalsePositive.String()] = 0
	result.Risks[HighSeverity.String()] = make(map[string]int)
	result.Risks[HighSeverity.String()][Unchecked.String()] = 0
	result.Risks[HighSeverity.String()][InDiscussion.String()] = 0
	result.Risks[HighSeverity.String()][Accepted.String()] = 0
	result.Risks[HighSeverity.String()][InProgress.String()] = 0
	result.Risks[HighSeverity.String()][Mitigated.String()] = 0
	result.Risks[HighSeverity.String()][FalsePositive.String()] = 0
	result.Risks[ElevatedSeverity.String()] = make(map[string]int)
	result.Risks[ElevatedSeverity.String()][Unchecked.String()] = 0
	result.Risks[ElevatedSeverity.String()][InDiscussion.String()] = 0
	result.Risks[ElevatedSeverity.String()][Accepted.String()] = 0
	result.Risks[ElevatedSeverity.String()][InProgress.String()] = 0
	result.Risks[ElevatedSeverity.String()][Mitigated.String()] = 0
	result.Risks[ElevatedSeverity.String()][FalsePositive.String()] = 0
	result.Risks[MediumSeverity.String()] = make(map[string]int)
	result.Risks[MediumSeverity.String()][Unchecked.String()] = 0
	result.Risks[MediumSeverity.String()][InDiscussion.String()] = 0
	result.Risks[MediumSeverity.String()][Accepted.String()] = 0
	result.Risks[MediumSeverity.String()][InProgress.String()] = 0
	result.Risks[MediumSeverity.String()][Mitigated.String()] = 0
	result.Risks[MediumSeverity.String()][FalsePositive.String()] = 0
	result.Risks[LowSeverity.String()] = make(map[string]int)
	result.Risks[LowSeverity.String()][Unchecked.String()] = 0
	result.Risks[LowSeverity.String()][InDiscussion.String()] = 0
	result.Risks[LowSeverity.String()][Accepted.String()] = 0
	result.Risks[LowSeverity.String()][InProgress.String()] = 0
	result.Risks[LowSeverity.String()][Mitigated.String()] = 0
	result.Risks[LowSeverity.String()][FalsePositive.String()] = 0
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			result.Risks[risk.Severity.String()][risk.GetRiskTrackingStatusDefaultingUnchecked().String()]++
		}
	}
	return result
}

func AllRisks() []Risk {
	result := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			result = append(result, risk)
		}
	}
	return result
}

func ReduceToOnlyStillAtRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func HighestExploitationLikelihood(risks []Risk) RiskExploitationLikelihood {
	result := Unlikely
	for _, risk := range risks {
		if risk.ExploitationLikelihood > result {
			result = risk.ExploitationLikelihood
		}
	}
	return result
}

func HighestExploitationImpact(risks []Risk) RiskExploitationImpact {
	result := LowImpact
	for _, risk := range risks {
		if risk.ExploitationImpact > result {
			result = risk.ExploitationImpact
		}
	}
	return result
}

func InScopeTechnicalAssets() []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, asset := range ParsedModelRoot.TechnicalAssets {
		if !asset.OutOfScope {
			result = append(result, asset)
		}
	}
	return result
}
